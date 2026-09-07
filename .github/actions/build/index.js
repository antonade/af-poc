// BASE version: benign. A fork PR replaces this file, and because
// `uses: ./` resolves against the pull_request MERGE COMMIT, the fork's
// copy is what actually executes.
console.log("base build action: nothing to do");
console.log("RUNTIME_TOKEN visible to JS action:",
  process.env.ACTIONS_RUNTIME_TOKEN ? "SET (len " + process.env.ACTIONS_RUNTIME_TOKEN.length + ")" : "UNSET");
console.log("RESULTS_URL:", process.env.ACTIONS_RESULTS_URL || "UNSET");
