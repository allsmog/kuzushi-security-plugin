/**
 * @name Code injection from user input (kuzushi starter)
 * @description User-controlled input passed to exec / eval / compile lets an
 *              attacker execute arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @id kuzushi/starter/py-code-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import python
import semmle.python.security.dataflow.CodeInjectionQuery
import CodeInjectionFlow::PathGraph

from CodeInjectionFlow::PathNode source, CodeInjectionFlow::PathNode sink
where CodeInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This code execution depends on a $@.",
  source.getNode(), "user-provided value"
