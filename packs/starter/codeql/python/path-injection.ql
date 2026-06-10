/**
 * @name Path traversal from user input (kuzushi starter)
 * @description User-controlled input used to build a filesystem path without
 *              containment lets an attacker read or write outside the intended
 *              directory.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id kuzushi/starter/py-path-injection
 * @tags security
 *       external/cwe/cwe-022
 */

import python
import semmle.python.security.dataflow.PathInjectionQuery
import PathInjectionFlow::PathGraph

from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This path depends on a $@.",
  source.getNode(), "user-provided value"
