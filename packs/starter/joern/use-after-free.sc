// kuzushi starter (Joern/CPG): a freed pointer's value reaching a later use (CWE-416).
// The freed pointer (the argument to free/delete/release) is the flow SOURCE; any later
// expression the freed value reaches by data flow is a candidate use-after-free — this is
// how an alias stored before the free, or a use on a fall-through/error path, gets caught
// that a single-function skim misses. Cross-function flows are exactly the lifetime bugs a
// reader can't hold in their head. Heuristic by nature (it can't model every realloc/own-
// transfer); treat hits as leads for /verify + /sanitize-pov (execution proof), not proof.
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

@main def exec(): Unit = {
importCpg(sys.env.getOrElse("KUZUSHI_CPG", sys.props.getOrElse("path",
  throw new RuntimeException("kuzushi-starter: missing KUZUSHI_CPG or -Dpath=<cpg>"))))

// Sources: the pointer handed to a release primitive (the value that is now dangling).
val sources = cpg.call.name("(?i)^(free|kfree|vfree|g_free|xfree|zfree|sdsfree|delete|release)$").argument.l
// Sinks: subsequent uses of a value — identifiers reached by data flow from the freed ptr.
val sinks = cpg.identifier.l
val flows = sinks.reachableByFlows(sources).take(25).l
System.err.println(s"[kuzushi-starter] CWE-416: ${sources.size} freed-ptrs, ${sinks.size} uses, ${flows.size} flows")
flows.foreach { p =>
  val els = p.elements
  if (els.size >= 2) {
    val src = els.head.location
    val snk = els.last.location
    // Only report a use STRICTLY AFTER the free in the same file (a plausible UAF order),
    // not the definition that precedes it.
    val sFile = Option(src.filename).getOrElse("")
    val kFile = Option(snk.filename).getOrElse("")
    val sLine = src.lineNumber.getOrElse(0)
    val kLine = snk.lineNumber.getOrElse(0)
    if (sFile != kFile || kLine > sLine) {
      println(s"""{"cwe":"CWE-416","filePath":"$kFile","sourceLine":$sLine,"sinkLine":$kLine}""")
    }
  }
}
}
