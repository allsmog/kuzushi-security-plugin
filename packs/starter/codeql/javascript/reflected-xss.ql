/**
 * @name Reflected cross-site scripting from user input (kuzushi starter)
 * @description User-controlled input written to a page without escaping lets an
 *              attacker run script in a victim's browser.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @id kuzushi/starter/js-reflected-xss
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript
import semmle.javascript.security.dataflow.ReflectedXssQuery
import ReflectedXssFlow::PathGraph

from ReflectedXssFlow::PathNode source, ReflectedXssFlow::PathNode sink
where ReflectedXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Cross-site scripting vulnerability due to a $@.",
  source.getNode(), "user-provided value"
