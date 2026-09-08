// Benign base64 decoding — NOT malware.
// Real-world pattern: decode an audio chunk or a config blob that arrived base64-encoded.
const b64 = "SGVsbG8gV29ybGQ=";
const fromBuffer = Buffer.from(b64, "base64").toString("utf8");
const fromAtob = atob(b64);
module.exports = { fromBuffer, fromAtob };
