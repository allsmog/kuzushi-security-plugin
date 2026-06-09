/**
 * @name Server-side request forgery from user input (kuzushi starter)
 * @description User-controlled input used as the target of an outbound request
 *              lets an attacker reach internal services.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id kuzushi/starter/js-request-forgery
 * @tags security
 *       external/cwe/cwe-918
 */

import javascript
import semmle.javascript.security.dataflow.RequestForgeryQuery
import RequestForgeryFlow::PathGraph

from RequestForgeryFlow::PathNode source, RequestForgeryFlow::PathNode sink
where RequestForgeryFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "The target of this request depends on a $@.",
  source.getNode(), "user-provided value"
