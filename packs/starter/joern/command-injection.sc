// kuzushi starter (Joern/CPG): user input -> shell-exec sink (CWE-78).
//
// Forward dataflow from common attacker-controlled sources (request fields,
// argv/env, deserialized body params) to process-execution sinks. Prints one
// flow per line as Joern's default `.p` rendering. Curated as a deep starter so
// the first interprocedural query needs no agent synthesis; the codeql/joern MCP
// servers run it only when its bytes match the digest-attested pack manifest.

@main def run() = {
  val sources = (
    cpg.call.name("(?i)(getParameter|getenv|getQuery|getHeader|getCookie|readBody)").l ++
    cpg.method.parameter.name("(?i)(req|request|argv|args|body|params|query|input)").l
  )
  val sinks = cpg.call.name(
    "(?i)(exec|execSync|execFile|system|popen|spawn|spawnSync|fork|Runtime\\.exec|os_system|subprocess|sh)"
  ).l
  sinks.reachableByFlows(sources).p.foreach(println)
}
