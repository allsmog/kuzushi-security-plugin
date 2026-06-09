// kuzushi starter (Joern/CPG): user input -> unsafe deserialization sink (CWE-502).
// NOTE: reaching the sink with attacker data is necessary but not sufficient for
// RCE — that depends on gadget chains in the loaded libraries, which a CPG query
// can't enumerate. Treat hits as leads for /verify + /poc, not proof.
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

importCpg(sys.env.getOrElse("KUZUSHI_CPG", sys.props.getOrElse("path",
  throw new RuntimeException("kuzushi-starter: missing KUZUSHI_CPG or -Dpath=<cpg>"))))

val sources = cpg.call.code(
  "(?i)(req\\.|request\\.|getParameter|\\.body\\b|\\.params\\b|\\.query\\b|\\.headers\\b|\\.cookies\\b|getInputStream)"
).l
val sinks = cpg.call.code(
  "(?i)(unserialize|readObject|ObjectInputStream|pickle\\.loads|cPickle\\.loads|yaml\\.load\\b|Marshal\\.load|deserialize|fromXML|readValue)"
).l
val flows = sinks.reachableByFlows(sources).take(25).l
System.err.println(s"[kuzushi-starter] CWE-502: ${sources.size} sources, ${sinks.size} sinks, ${flows.size} flows")
flows.foreach { p =>
  val els = p.elements
  if (els.nonEmpty) {
    val src = els.head.location
    val snk = els.last.location
    val file = Option(snk.filename).getOrElse("")
    println(s"""{"cwe":"CWE-502","filePath":"$file","sourceLine":${src.lineNumber.getOrElse(0)},"sinkLine":${snk.lineNumber.getOrElse(0)}}""")
  }
}
