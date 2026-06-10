/**
 * @name SQL injection from user input (kuzushi starter)
 * @description User-controlled input concatenated into a SQL query lets an
 *              attacker alter the query.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id kuzushi/starter/js-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import javascript
import semmle.javascript.security.dataflow.SqlInjectionQuery
import SqlInjectionFlow::PathGraph

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This query depends on a $@.",
  source.getNode(), "user-provided value"
