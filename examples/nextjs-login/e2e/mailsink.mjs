// A Standard-Webhooks-free mail sink for the parity run: IAMKit's
// deployment email webhook posts every message here (code, token, link);
// the tests read them back with GET /messages.
import { createServer } from "node:http";

const port = Number(process.env.MAIL_SINK_PORT ?? 18025);
const messages = [];

createServer((req, res) => {
  if (req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      try {
        messages.push(JSON.parse(body));
      } catch {
        // ignore malformed bodies
      }
      res.writeHead(204).end();
    });
    return;
  }
  if (req.method === "GET" && req.url === "/messages") {
    res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(messages));
    return;
  }
  res.writeHead(404).end();
}).listen(port, "127.0.0.1", () => console.log(`mail sink on 127.0.0.1:${port}`));
