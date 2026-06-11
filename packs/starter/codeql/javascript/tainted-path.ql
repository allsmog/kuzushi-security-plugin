/**
 * @name Path traversal from user input (kuzushi starter)
 * @description User-controlled input used to build a filesystem path without
 *              containment lets an attacker access files outside the intended
 *              directory.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id kuzushi/starter/js-tainted-path
 * @tags security
 *       external/cwe/cwe-022
 */

import javascript
import semmle.javascript.security.dataflow.TaintedPathQuery
import TaintedPathFlow::PathGraph

from TaintedPathFlow::PathNode source, TaintedPathFlow::PathNode sink
where TaintedPathFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This path depends on a $@.",
  source.getNode(), "user-provided value"
