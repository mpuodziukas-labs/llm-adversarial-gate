// A small REST API over the gate, on node:http with no framework.
//
//   POST /v1/check  {"text": string}  ->  200 {"decision","category"}
//   GET  /healthz                     ->  200 {"status":"ok"}
//
// Errors carry a fixed machine-readable code and nothing else: no stack traces, no
// rule ids, no echo of the input.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { evaluate, summarize } from "./gate.js";

/** Request body cap in bytes (the gate's own cap is 100000 code points of text). */
export const MAX_BODY_BYTES = 256 * 1024;

type Json = Record<string, unknown>;

function send(res: ServerResponse, status: number, body: Json, headers: Record<string, string> = {}): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...headers,
  });
  res.end(payload);
}

/** Read the body, or return null if it exceeds the cap (the rest is drained and discarded). */
function readBody(req: IncomingMessage): Promise<Buffer | null> {
  const declared = Number(req.headers["content-length"]);
  const tooBig = Number.isFinite(declared) && declared > MAX_BODY_BYTES;
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let over = tooBig;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) over = true;
      if (!over) chunks.push(chunk);
      else chunks.length = 0;
    });
    req.on("end", () => resolve(over ? null : Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function parseText(body: Buffer): { text: string } | { error: "invalid_json" | "text_required" } {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    return { error: "invalid_json" };
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return { error: "text_required" };
  const text = (value as Json)["text"];
  return typeof text === "string" ? { text } : { error: "text_required" };
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = (req.url ?? "").split("?")[0];
  if (path === "/healthz") {
    if (req.method !== "GET") return send(res, 405, { error: "method_not_allowed" }, { allow: "GET" });
    return send(res, 200, { status: "ok" });
  }
  if (path === "/v1/check") {
    if (req.method !== "POST") return send(res, 405, { error: "method_not_allowed" }, { allow: "POST" });
    const body = await readBody(req);
    if (body === null) return send(res, 413, { error: "payload_too_large" });
    const parsed = parseText(body);
    if ("error" in parsed) return send(res, 400, { error: parsed.error });
    return send(res, 200, { ...summarize(evaluate(parsed.text)) });
  }
  return send(res, 404, { error: "not_found" });
}

export function createApp(): Server {
  return createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) send(res, 500, { error: "internal_error" });
      else res.end();
    });
  });
}
