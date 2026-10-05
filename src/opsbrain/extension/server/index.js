// OpsBrain launcher for Claude Desktop: starts `opsbrain serve` and relays the MCP stream byte for byte.
// No dependencies, no logic, no credentials.
//
// The streams are piped explicitly. Claude Desktop runs this file in its built-in Node as an Electron
// UtilityProcess, whose stdin / stdout are not inheritable file descriptors: with `stdio: "inherit"` the child
// sees a closed stdin and exits right after `initialize`.
"use strict";
const { spawn } = require("node:child_process");

const binary = process.env.OPSBRAIN_BIN;
if (!binary) {
  console.error("opsbrain: OPSBRAIN_BIN is not set; reinstall with `opsbrain desktop install`");
  process.exit(1);
}
const child = spawn(binary, ["serve"], { stdio: ["pipe", "pipe", "pipe"], env: process.env });
child.on("error", (error) => {
  console.error(`opsbrain: cannot start ${binary}: ${error.message}`);
  process.exit(1);
});
process.stdin.pipe(child.stdin);
child.stdout.pipe(process.stdout);
child.stderr.pipe(process.stderr);
child.stdin.on("error", () => {}); // the server went away first: `exit` below reports it
process.stdin.on("end", () => child.stdin.end());
child.on("exit", (code, signal) => process.exit(signal ? 1 : code ?? 1));
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => child.kill(signal));
