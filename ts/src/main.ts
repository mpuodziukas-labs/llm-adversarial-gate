// Process entry point: PORT (default 8080, 0 = ephemeral) and HOST (default localhost).

import { createApp } from "./server.js";

const port = Number(process.env["PORT"] ?? "8080");
const host = process.env["HOST"] ?? "localhost";
const server = createApp();

server.listen(port, host, () => {
  const addr = server.address();
  const bound = typeof addr === "object" && addr !== null ? addr.port : port;
  console.log(`LISTENING ${host}:${bound}`);
});

function stop(): void {
  server.close(() => process.exit(0));
  server.closeAllConnections();
}

process.on("SIGTERM", stop);
process.on("SIGINT", stop);
