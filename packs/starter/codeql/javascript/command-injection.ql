/**
 * @name Command injection from user input (kuzushi starter)
 * @description User-controlled input flowing into a shell command lets an
 *              attacker execute arbitrary commands.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id kuzushi/starter/js-command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import javascript
import semmle.javascript.security.dataflow.CommandInjectionQuery
import DataFlow::PathGraph

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Command line depends on a $@.",
  source.getNode(), "user-provided value"
