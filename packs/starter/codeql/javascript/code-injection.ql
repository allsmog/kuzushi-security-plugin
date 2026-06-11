/**
 * @name Code injection from user input (kuzushi starter)
 * @description User-controlled input interpreted as code (eval / Function /
 *              dynamic require) lets an attacker execute arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @id kuzushi/starter/js-code-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import javascript
import semmle.javascript.security.dataflow.CodeInjectionQuery
import CodeInjectionFlow::PathGraph

from CodeInjectionFlow::PathNode source, CodeInjectionFlow::PathNode sink
where CodeInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This code execution depends on a $@.",
  source.getNode(), "user-provided value"
