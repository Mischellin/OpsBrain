// OpsBrain launcher for Claude Desktop: starts `opsbrain serve` and hands it this process's stdio, so the MCP
// stream passes through untouched. No dependencies, no logic, no credentials.
"use strict";
const { spawn } = require("node:child_process");

const binary = process.env.OPSBRAIN_BIN;
if (!binary) {
  console.error("opsbrain: OPSBRAIN_BIN is not set; reinstall with `opsbrain desktop install`");
  process.exit(1);
}
const child = spawn(binary, ["serve"], { stdio: "inherit", env: process.env });
child.on("error", (error) => {
  console.error(`opsbrain: cannot start ${binary}: ${error.message}`);
  process.exit(1);
});
child.on("exit", (code, signal) => process.exit(signal ? 1 : code ?? 1));
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => child.kill(signal));
