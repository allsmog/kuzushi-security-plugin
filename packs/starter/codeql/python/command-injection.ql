/**
 * @name Command injection from user input (kuzushi starter)
 * @description User-controlled input flowing into a shell command lets an
 *              attacker execute arbitrary commands.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id kuzushi/starter/py-command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.security.dataflow.CommandInjectionQuery
import CommandInjectionFlow::PathGraph

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This command depends on a $@.",
  source.getNode(), "user-provided value"
