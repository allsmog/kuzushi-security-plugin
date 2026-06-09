// kuzushi starter (Joern/CPG): user input -> redirect Location sink (CWE-601).
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

importCpg(sys.env.getOrElse("KUZUSHI_CPG", sys.props.getOrElse("path",
  throw new RuntimeException("kuzushi-starter: missing KUZUSHI_CPG or -Dpath=<cpg>"))))

val sources = cpg.call.code(
  "(?i)(req\\.|request\\.|getParameter|\\.body\\b|\\.params\\b|\\.query\\b|\\.headers\\b|\\.cookies\\b)"
).l
val sinks = cpg.call.code(
  "(?i)(redirect|sendRedirect|\\.location\\b|Location:|res\\.writeHead|setHeader\\(\\s*['\"]Location|HttpResponseRedirect|url_for)"
).l
val flows = sinks.reachableByFlows(sources).take(25).l
System.err.println(s"[kuzushi-starter] CWE-601: ${sources.size} sources, ${sinks.size} sinks, ${flows.size} flows")
flows.foreach { p =>
  val els = p.elements
  if (els.nonEmpty) {
    val src = els.head.location
    val snk = els.last.location
    val file = Option(snk.filename).getOrElse("")
    println(s"""{"cwe":"CWE-601","filePath":"$file","sourceLine":${src.lineNumber.getOrElse(0)},"sinkLine":${snk.lineNumber.getOrElse(0)}}""")
  }
}
