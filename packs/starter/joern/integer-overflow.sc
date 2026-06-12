// kuzushi starter (Joern/CPG): untrusted/parsed value -> allocation or copy SIZE (CWE-190 → CWE-787/125).
// An input-derived length/count reaching a malloc/realloc/memcpy size operand is the
// classic integer-overflow → undersized-allocation → out-of-bounds path. Reaching the
// size with input is necessary but not sufficient: whether it WRAPS depends on the
// operand width and the missing guard, which /verify (concolic) settles. Treat hits as
// leads, not proof — and note these are exactly the bugs a small-input fuzzer can't reach.
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

@main def exec(): Unit = {
importCpg(sys.env.getOrElse("KUZUSHI_CPG", sys.props.getOrElse("path",
  throw new RuntimeException("kuzushi-starter: missing KUZUSHI_CPG or -Dpath=<cpg>"))))

// Sources: values that come from outside or from parsing — the place an attacker sets a length.
// Includes embedded-interpreter argument readers (Lua `luaL_optint`/`luaL_checkint`, Python
// `PyArg_ParseTuple`, …): a script-controlled integer is attacker input just like a network
// length, and the C-only source list missed it (measured: 0 flows on the redis Lua CVEs).
// NOTE: Joern's `.code()` is a FULL-match — the pattern must match the entire call code,
// so it is wrapped in `.*….*` to match a call whose text CONTAINS the idiom (measured:
// without the wrap `luaL_optint` matched 0 calls; with it, 64).
val sources = cpg.call.code(
  "(?i).*(recv|recvfrom|read\\(|fread|fgets|getline|scanf|ntohl|ntohs|ntohll|be32toh|be64toh|strtol|strtoul|atoi|atol|getParameter|\\.body\\b|\\.params\\b|\\.query\\b|\\.headers\\b|luaL_(check|opt)(int|long|integer|number|unsigned)|lua_to(integer|number|unsigned)|PyArg_Parse|PyLong_As).*"
).l
// Sinks: allocation / copy size operands AND interpreter stack/array sizing where an
// overflowed length becomes an OOB. `lua_checkstack`/`luaL_checkstack` take an attacker-derived
// element count (the redis `luaB_unpack` CVE-2025-46817 shape: `n = e - i + 1` → checkstack(n)).
val sinks = cpg.call.code(
  "(?i).*(malloc|calloc|realloc|alloca|zmalloc|zrealloc|xmalloc|kmalloc|memcpy|memmove|memset|strncpy|strncat|snprintf|lua_checkstack|luaL_checkstack|lua_createtable|luaM_(new|realloc|malloc)\\w*).*"
).l
val flows = sinks.reachableByFlows(sources).take(25).l
System.err.println(s"[kuzushi-starter] CWE-190: ${sources.size} sources, ${sinks.size} sinks, ${flows.size} flows")
flows.foreach { p =>
  val els = p.elements
  if (els.nonEmpty) {
    val src = els.head.location
    val snk = els.last.location
    val file = Option(snk.filename).getOrElse("")
    println(s"""{"cwe":"CWE-190","filePath":"$file","sourceLine":${src.lineNumber.getOrElse(0)},"sinkLine":${snk.lineNumber.getOrElse(0)}}""")
  }
}
}
