// A minimal TLS-terminating reverse proxy for the parity run: IAMKit's
// issuer, redirect URIs and __Host- cookies need HTTPS. Maps
// PROXY_ROUTES="19443=18080,13443=13000" (https port = http upstream port)
// with the certificate in TLS_CERT/TLS_KEY.
import { readFileSync } from "node:fs";
import { request } from "node:http";
import { createServer } from "node:https";

const tls = { cert: readFileSync(process.env.TLS_CERT), key: readFileSync(process.env.TLS_KEY) };

for (const pair of process.env.PROXY_ROUTES.split(",")) {
  const [listen, upstream] = pair.split("=").map(Number);
  createServer(tls, (req, res) => {
    const headers = { ...req.headers, "x-forwarded-proto": "https", "x-forwarded-host": req.headers.host };
    const out = request({ host: "127.0.0.1", port: upstream, method: req.method, path: req.url, headers }, (back) => {
      res.writeHead(back.statusCode ?? 502, back.headers);
      back.pipe(res);
    });
    out.on("error", () => res.writeHead(502).end());
    req.pipe(out);
  }).listen(listen, "127.0.0.1", () => console.log(`https://localhost:${listen} → http://127.0.0.1:${upstream}`));
}
