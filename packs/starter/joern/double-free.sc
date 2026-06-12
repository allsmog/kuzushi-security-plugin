// kuzushi starter (Joern/CPG): a freed pointer's value reaching a SECOND free (CWE-415).
// Source = the pointer argument at one release; sink = the pointer argument at any release.
// A data flow between them means the same value can be freed twice (e.g. an error path and a
// cleanup path both reach free without nulling the pointer between). Heuristic — it can't
// prove the two frees are reachable on one execution; treat hits as leads for /verify and
// the execution lane (/sanitize-pov double-free aborts under ASan are the proof).
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

@main def exec(): Unit = {
importCpg(sys.env.getOrElse("KUZUSHI_CPG", sys.props.getOrElse("path",
  throw new RuntimeException("kuzushi-starter: missing KUZUSHI_CPG or -Dpath=<cpg>"))))

val freeArgs = cpg.call.name("(?i)^(free|kfree|vfree|g_free|xfree|zfree|sdsfree|delete)$").argument.l
val sources = freeArgs
val sinks = freeArgs
val flows = sinks.reachableByFlows(sources).take(25).l
System.err.println(s"[kuzushi-starter] CWE-415: ${freeArgs.size} free-args, ${flows.size} flows")
flows.foreach { p =>
  val els = p.elements
  if (els.size >= 2) {
    val src = els.head.location
    val snk = els.last.location
    val sLine = src.lineNumber.getOrElse(0)
    val kLine = snk.lineNumber.getOrElse(0)
    // Distinct free sites only (a value flowing from one free to a later, different free).
    if (kLine != sLine) {
      val file = Option(snk.filename).getOrElse("")
      println(s"""{"cwe":"CWE-415","filePath":"$file","sourceLine":$sLine,"sinkLine":$kLine}""")
    }
  }
}
}
