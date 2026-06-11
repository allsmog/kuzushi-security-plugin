/**
 * @name Server-side request forgery from user input (kuzushi starter)
 * @description User-controlled input used as the target of an outbound request
 *              lets an attacker reach internal services.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id kuzushi/starter/py-request-forgery
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.security.dataflow.ServerSideRequestForgeryQuery
import FullServerSideRequestForgeryFlow::PathGraph

from FullServerSideRequestForgeryFlow::PathNode source, FullServerSideRequestForgeryFlow::PathNode sink
where FullServerSideRequestForgeryFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "The target of this request depends on a $@.",
  source.getNode(), "user-provided value"
