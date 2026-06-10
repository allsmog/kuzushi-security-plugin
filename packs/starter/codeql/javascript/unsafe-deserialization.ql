/**
 * @name Unsafe deserialization of user input (kuzushi starter)
 * @description Deserializing attacker-controlled data can lead to code execution
 *              via gadget chains in the loaded libraries.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id kuzushi/starter/js-unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import javascript
import semmle.javascript.security.dataflow.UnsafeDeserializationQuery
import UnsafeDeserializationFlow::PathGraph

from UnsafeDeserializationFlow::PathNode source, UnsafeDeserializationFlow::PathNode sink
where UnsafeDeserializationFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe deserialization depends on a $@.",
  source.getNode(), "user-provided value"
