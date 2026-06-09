// kuzushi starter (Joern/CPG): user input -> template render sink (CWE-1336, SSTI).
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

importCpg(sys.env.getOrElse("KUZUSHI_CPG", sys.props.getOrElse("path",
  throw new RuntimeException("kuzushi-starter: missing KUZUSHI_CPG or -Dpath=<cpg>"))))

val sources = cpg.call.code(
  "(?i)(req\\.|request\\.|getParameter|\\.body\\b|\\.params\\b|\\.query\\b|\\.headers\\b|\\.cookies\\b)"
).l
val sinks = cpg.call.code(
  "(?i)(render_template_string|from_string|Template\\(|\\.render\\(|compile\\(.*template|Handlebars\\.compile|ejs\\.render|pug\\.compile|Velocity|Freemarker)"
).l
val flows = sinks.reachableByFlows(sources).take(25).l
System.err.println(s"[kuzushi-starter] CWE-1336: ${sources.size} sources, ${sinks.size} sinks, ${flows.size} flows")
flows.foreach { p =>
  val els = p.elements
  if (els.nonEmpty) {
    val src = els.head.location
    val snk = els.last.location
    val file = Option(snk.filename).getOrElse("")
    println(s"""{"cwe":"CWE-1336","filePath":"$file","sourceLine":${src.lineNumber.getOrElse(0)},"sinkLine":${snk.lineNumber.getOrElse(0)}}""")
  }
}
