export function oracleVerdict({ exploitRegressionPassed = false, functionalRegressionPassed = false, semanticRegressionPassed = false } = {}) {
  const pocPlusPassed = Boolean(exploitRegressionPassed && functionalRegressionPassed && semanticRegressionPassed);
  return {
    exploitRegressionPassed: Boolean(exploitRegressionPassed),
    functionalRegressionPassed: Boolean(functionalRegressionPassed),
    semanticRegressionPassed: Boolean(semanticRegressionPassed),
    pocPlusPassed
  };
}

export function makeOracle({ id, cwes, description, positiveControl, negativeControl, exploitRegression, behaviorPreservation, pocPlus }) {
  return {
    id,
    cwes,
    description,
    controls: { positiveControl, negativeControl, exploitRegression, behaviorPreservation, pocPlus },
    evaluate: oracleVerdict
  };
}
