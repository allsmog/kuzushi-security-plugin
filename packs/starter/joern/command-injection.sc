// kuzushi starter (Joern/CPG): user input -> shell-exec sink (CWE-78).
//
// Forward interprocedural dataflow from attacker-controlled sources to process-
// execution sinks. Run via the joern MCP server, which loads the CPG path from
// KUZUSHI_CPG (the same convention as scripts/joern/taint-flows.sc) — so this is a
// top-level script (no @main) that calls importCpg itself. Emits one JSON line per
// flow on stdout; logs go to stderr.
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

importCpg(sys.env.getOrElse("KUZUSHI_CPG", sys.props.getOrElse("path",
  throw new RuntimeException("kuzushi-starter: missing KUZUSHI_CPG or -Dpath=<cpg>"))))

val sources = cpg.call.code(
  "(?i)(req\\.|request\\.|getParameter|getenv|process\\.argv|\\bargv\\b|\\.body\\b|\\.params\\b|\\.query\\b|\\.headers\\b|\\.cookies\\b|read[lL]ine|getInputStream)"
).l
val sinks = cpg.call.code(
  "(?i)(\\bexec\\b|execSync|execFile|\\bsystem\\(|popen|\\bspawn|Runtime\\.exec|os\\.system|subprocess\\.|ProcessBuilder|sh -c)"
).l
val flows = sinks.reachableByFlows(sources).take(25).l
System.err.println(s"[kuzushi-starter] CWE-78: ${sources.size} sources, ${sinks.size} sinks, ${flows.size} flows")
flows.foreach { p =>
  val els = p.elements
  if (els.nonEmpty) {
    val src = els.head.location
    val snk = els.last.location
    val file = Option(snk.filename).getOrElse("")
    println(s"""{"cwe":"CWE-78","filePath":"$file","sourceLine":${src.lineNumber.getOrElse(0)},"sinkLine":${snk.lineNumber.getOrElse(0)}}""")
  }
}
