// Minimal MCP stdio caller, used by the acceptance script to talk to a hand
// directly (the "human" side of a scope / high-auth decision).
//
// usage: node scripts/mcp-call.cjs <cwd> <script> <tool> [jsonArgs|@file]
const { spawn } = require("child_process");
const fs = require("fs");

const [cwd, script, tool, rawArgs] = process.argv.slice(2);
if (!cwd || !script || !tool) {
  console.error("usage: node mcp-call.cjs <cwd> <script> <tool> [jsonArgs|@file]");
  process.exit(2);
}
const args = rawArgs
  ? JSON.parse(rawArgs.startsWith("@") ? fs.readFileSync(rawArgs.slice(1), "utf8") : rawArgs)
  : {};

const p = spawn(process.execPath, script.split(" "), { cwd });
p.stderr.on("data", (d) => process.stderr.write(d));
p.on("error", (e) => {
  console.error("spawn failed:", e.message);
  process.exit(1);
});

const send = (o) => p.stdin.write(JSON.stringify(o) + "\n");

let pending = "";
let settled = false;
function settle(code, payload) {
  if (settled) return;
  settled = true;
  clearTimeout(timer);
  if (payload) console.log(payload);
  try {
    p.stdin.end();
  } catch {}
  p.kill();
  process.exit(code);
}

p.stdout.on("data", (chunk) => {
  pending += chunk.toString("utf8");
  let idx;
  while ((idx = pending.indexOf("\n")) >= 0) {
    const line = pending.slice(0, idx).trim();
    pending = pending.slice(idx + 1);
    if (!line) continue;
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      continue;
    }
    if (m.id === 2) {
      if (m.error) settle(1, "rpc error: " + JSON.stringify(m.error));
      else {
        const text = (m.result.content || []).map((c) => c.text || "").join("\n");
        settle(m.result.isError ? 1 : 0, text);
      }
    }
  }
});

const timer = setTimeout(() => {
  console.error("timeout waiting for " + tool);
  settle(1);
}, 60000);

send({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "youkai-acceptance", version: "0" },
  },
});
send({ jsonrpc: "2.0", method: "notifications/initialized" });
send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: tool, arguments: args } });
