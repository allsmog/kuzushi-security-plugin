// taint-analysis Joern dataflow query (ported from kuzushi taint-iris-next
// scripts/taint_iris_next_flows.sc). For each per-CWE source/sink regex pair it
// runs `cpg.call.code(<sink>).reachableByFlows(cpg.call.code(<source>))` and
// emits one JSON object per flow path on stdout.
//
// HOW THE PLUGIN CALLS THIS: the joern MCP server (mcp/servers/joern.mjs) runs
//   joern --script - -Dpath=<cpg>
// with this script piped on stdin. So:
//   * the CPG path arrives as KUZUSHI_CPG (and, for older callers, JVM property `path`), and
//   * the per-CWE queries are INLINED into QUERIES_JSON below (the MCP tool has
//     no --param/env channel). The flow-tracer subagent reads this file, replaces
//     the QUERIES_JSON value with the array it built from the labeled
//     sinks/sources, and sends the whole script as the joern:query `script` arg.
//
// QUERIES_JSON shape (replace the [] below, keep the triple-quotes):
//   [ { "cwe": "CWE-89", "taintClass": "sql-injection",
//       "sourceRegex": "(req\\.query|request\\.args)",
//       "sinkRegex":   "(db\\.query|\\.execute\\()" }, ... ]
//
// Each flow becomes one stdout line:
//   {"cwe":"CWE-89","taintClass":"sql-injection","filePath":"src/routes/users.ts",
//    "sourceLine":12,"sinkLine":13,"sourceCode":"...","sinkCode":"...",
//    "steps":[{"file":"...","line":12,"code":"..."}, ...]}
// Non-flow output (logs) goes to stderr; the caller parses stdout line-by-line.

import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.joern.dataflowengineoss.language._
import scala.util.Try
import java.util.concurrent.{Callable, Executors, TimeUnit, TimeoutException}

// Modern Joern's --script runner requires an @main entrypoint; the executable body
// lives here while the helper defs + case class stay top-level (below). Token
// replacement (QUERIES_JSON / DIRECTION) is textual, so it is unaffected. The name
// must NOT be `run` — Joern's ScalaReplPP wrapper already defines a `run` member.
@main def exec(): Unit = {
// === REPLACE THE [] BELOW WITH THE PER-CWE QUERIES ARRAY ===================
val QUERIES_JSON: String = """[]"""
// Flow direction. "forward" (default): sinks.reachableByFlows(sources) — for the
// labeled sources, which sinks do they taint. "backward": sources.reachableByFlows(sinks)
// — root at the dangerous sink and trace which sources reach it (useful when a
// sink is known but sources aren't pre-labeled). The flow-tracer replaces this
// token like QUERIES_JSON; existing callers that don't set it get "forward".
val DIRECTION: String = "forward"
// ===========================================================================

val cpgFile: String = sys.env.get("KUZUSHI_CPG")
  .orElse(sys.props.get("path"))
  .getOrElse(throw new RuntimeException("taint-flows: missing KUZUSHI_CPG or -Dpath=<cpg>"))
importCpg(cpgFile)

val queries = parseQueries(QUERIES_JSON)
System.err.println(s"[taint-analysis] loaded ${queries.size} CWE queries")

// Hard caps keep `reachableByFlows` tractable on large CPGs (the cross-product
// flow analysis is exponential); Joern's ranker surfaces the shortest paths first.
val maxSourcesPerCwe = 200
val maxSinksPerCwe = 200
val maxFlowsPerCwe = 25
// Per-CWE wall-clock budget; one broad pattern can otherwise deadlock the run.
// Default 60s; set KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS=<N> to widen, 0 to disable.
val perCweTimeoutMs: Long = Option(System.getenv("KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS"))
  .flatMap(s => Try(s.toLong).toOption)
  .getOrElse(60000L)
// Single-thread executor: joern's iterator traversals don't honor interruption,
// so a cancelled task may keep running — bound to one worker to cap peak memory.
val executor = Executors.newSingleThreadExecutor()
try {
  for (q <- queries) {
    val sources = Try(cpg.call.code(q.sourceRegex).take(maxSourcesPerCwe).l).getOrElse(Nil)
    val sinks = Try(cpg.call.code(q.sinkRegex).take(maxSinksPerCwe).l).getOrElse(Nil)
    System.err.println(s"[taint-analysis] ${q.cwe}: ${sources.size} sources (cap $maxSourcesPerCwe), ${sinks.size} sinks (cap $maxSinksPerCwe)")
    if (sources.nonEmpty && sinks.nonEmpty) {
      val task: Callable[List[io.joern.dataflowengineoss.language.Path]] = () =>
        (if (DIRECTION == "backward") sources.reachableByFlows(sinks)
         else sinks.reachableByFlows(sources)).take(maxFlowsPerCwe).l
      val future = executor.submit(task)
      val flowsOpt =
        if (perCweTimeoutMs <= 0L) Try(future.get()).toOption
        else
          try Some(future.get(perCweTimeoutMs, TimeUnit.MILLISECONDS))
          catch {
            case _: TimeoutException =>
              future.cancel(true)
              System.err.println(s"[taint-analysis] ${q.cwe}: TIMEOUT after ${perCweTimeoutMs}ms; skipping")
              None
            case t: Throwable =>
              System.err.println(s"[taint-analysis] ${q.cwe}: ERROR ${t.getClass.getSimpleName}: ${t.getMessage}; skipping")
              None
          }
      val flows = flowsOpt.getOrElse(Nil)
      System.err.println(s"[taint-analysis] ${q.cwe}: ${flows.size} flows")
      for (flow <- flows) emitFlow(q, flow)
    }
  }
} finally {
  executor.shutdownNow()
}
} // end @main exec()

case class CweQuery(cwe: String, taintClass: String, sourceRegex: String, sinkRegex: String)

def parseQueries(raw: String): List[CweQuery] = {
  val inner = raw.trim.stripPrefix("[").stripSuffix("]").trim
  if (inner.isEmpty) return Nil
  splitObjects(inner).map(parseObject)
}

def splitObjects(s: String): List[String] = {
  val out = scala.collection.mutable.ListBuffer.empty[String]
  var depth = 0
  var start = -1
  var inString = false
  var escape = false
  for (i <- 0 until s.length) {
    val ch = s.charAt(i)
    if (escape) escape = false
    else if (inString) {
      if (ch == '\\') escape = true
      else if (ch == '"') inString = false
    } else {
      if (ch == '"') inString = true
      else if (ch == '{') { if (depth == 0) start = i; depth += 1 }
      else if (ch == '}') { depth -= 1; if (depth == 0 && start >= 0) { out += s.substring(start, i + 1); start = -1 } }
    }
  }
  out.toList
}

def parseObject(obj: String): CweQuery =
  CweQuery(readString(obj, "cwe"), readString(obj, "taintClass"), readString(obj, "sourceRegex"), readString(obj, "sinkRegex"))

def readString(obj: String, key: String): String = {
  val needle = "\"" + key + "\""
  val keyIdx = obj.indexOf(needle)
  if (keyIdx < 0) return ""
  val after = obj.substring(keyIdx + needle.length)
  val colonIdx = after.indexOf(':')
  if (colonIdx < 0) return ""
  val afterColon = after.substring(colonIdx + 1).dropWhile(_.isWhitespace)
  if (!afterColon.startsWith("\"")) return ""
  val body = afterColon.substring(1)
  val sb = new StringBuilder
  var i = 0
  var escape = false
  while (i < body.length) {
    val ch = body.charAt(i)
    if (escape) {
      ch match {
        case 'n' => sb.append('\n'); case 't' => sb.append('\t'); case 'r' => sb.append('\r')
        case '\\' => sb.append('\\'); case '"' => sb.append('"'); case '/' => sb.append('/')
        case other => sb.append(other)
      }
      escape = false; i += 1
    } else if (ch == '\\') { escape = true; i += 1 }
    else if (ch == '"') return sb.toString
    else { sb.append(ch); i += 1 }
  }
  sb.toString
}

def emitFlow(q: CweQuery, flow: io.joern.dataflowengineoss.language.Path): Unit = {
  val elements = flow.elements
  if (elements.isEmpty) return
  val first = elements.head
  val last = elements.last
  val filename = Option(first.location.filename).getOrElse("")
  val sourceLine = first.location.lineNumber.getOrElse(0)
  val sinkLine = last.location.lineNumber.getOrElse(0)
  val sourceCode = trimCode(first.code)
  val sinkCode = trimCode(last.code)
  val steps = elements.map { e =>
    val f = Option(e.location.filename).getOrElse("")
    val l = e.location.lineNumber.getOrElse(0)
    val c = trimCode(e.code)
    s"""{"file":${jsonEscape(f)},"line":$l,"code":${jsonEscape(c)}}"""
  }
  val payload = s"""{"cwe":${jsonEscape(q.cwe)},"taintClass":${jsonEscape(q.taintClass)},"filePath":${jsonEscape(filename)},"sourceLine":$sourceLine,"sinkLine":$sinkLine,"sourceCode":${jsonEscape(sourceCode)},"sinkCode":${jsonEscape(sinkCode)},"steps":[${steps.mkString(",")}]}"""
  println(payload)
}

def trimCode(code: String): String = {
  val collapsed = code.linesIterator.map(_.trim).mkString(" ")
  if (collapsed.length > 240) collapsed.substring(0, 240) + "..." else collapsed
}

def jsonEscape(s: String): String = {
  val sb = new StringBuilder
  sb.append('"')
  for (ch <- s) ch match {
    case '"' => sb.append("\\\"")
    case '\\' => sb.append("\\\\")
    case '\n' => sb.append("\\n")
    case '\r' => sb.append("\\r")
    case '\t' => sb.append("\\t")
    case c if c < 0x20 => sb.append("\\u%04x".format(c.toInt))
    case c => sb.append(c)
  }
  sb.append('"')
  sb.toString
}
