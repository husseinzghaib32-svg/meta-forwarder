import crypto from "crypto";

export const config = { api: { bodyParser: false } };

function readRaw(req) {
return new Promise((resolve, reject) => {
const chunks = [];
req.on("data", (c) => chunks.push(c));
req.on("end", () => resolve(Buffer.concat(chunks)));
req.on("error", reject);
});
}

export default async function handler(req, res) {
if (req.method === "GET") {
const mode = req.query["hub.mode"];
const token = req.query["hub.verify_token"];
const challenge = req.query["hub.challenge"];
if (mode === "subscribe" && token === process.env.VERIFY_TOKEN) {
res.setHeader("Content-Type", "text/plain");
return res.status(200).send(challenge);
}
return res.status(403).send("Forbidden");
}

if (req.method === "POST") {
const raw = await readRaw(req);
const sig = req.headers["x-hub-signature-256"] || "";
const expected =
"sha256=" +
crypto.createHmac("sha256", process.env.APP_SECRET).update(raw).digest("hex");
const a = Buffer.from(sig);
const b = Buffer.from(expected);
if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
return res.status(401).send("Bad signature");
}
await fetch(process.env.TWIN_URL, {
method: "POST",
headers: { "content-type": "application/json" },
body: raw.toString("utf8"),
});
return res.status(200).send("OK");
}

return res.status(405).send("Method not allowed");
}
