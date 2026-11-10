// WebAuthn registration (random challenge, direct attestation) + attestation verification.
// No dependencies. Needs a secure context (https or localhost).
// Supports fmt "packed" (with x5c) and "fido-u2f". No MDS / AAGUID lookup.

// ---------- small helpers ----------
const enc = new TextEncoder(), dec = new TextDecoder();
const sha256 = (d) => crypto.subtle.digest("SHA-256", d);
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const concat = (...a) => {
  const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let p = 0;
  for (const x of a) { o.set(x, p); p += x.length; }
  return o;
};

// ---------- minimal CBOR decoder (returns [value, nextOffset]) ----------
function cborDecode(bytes, off = 0) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  function read() {
    const ib = bytes[off++], major = ib >> 5, ai = ib & 31;
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22 || ai === 23) return null;
      throw new Error("Unsupported CBOR simple/float value");
    }
    let n;
    if (ai < 24) n = ai;
    else if (ai === 24) n = bytes[off++];
    else if (ai === 25) { n = dv.getUint16(off); off += 2; }
    else if (ai === 26) { n = dv.getUint32(off); off += 4; }
    else if (ai === 27) { n = Number(dv.getBigUint64(off)); off += 8; }
    else throw new Error("Unsupported CBOR length encoding");
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { const v = bytes.subarray(off, off + n); off += n; return v; }
      case 3: { const v = dec.decode(bytes.subarray(off, off + n)); off += n; return v; }
      case 4: { const a = []; for (let i = 0; i < n; i++) a.push(read()); return a; }
      case 5: { const m = new Map(); for (let i = 0; i < n; i++) { const k = read(); m.set(k, read()); } return m; }
      default: throw new Error("Unsupported CBOR major type " + major);
    }
  }
  const value = read();
  return [value, off];
}

// ---------- minimal DER / X.509 parser ----------
function asn1(bytes, off = 0) {
  const tag = bytes[off];
  let len = bytes[off + 1], p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[p++];
  }
  return { tag, start: off, vStart: p, vEnd: p + len, end: p + len, buf: bytes };
}
const children = (n) => {
  const out = [];
  for (let p = n.vStart; p < n.vEnd;) { const c = asn1(n.buf, p); out.push(c); p = c.end; }
  return out;
};
const rawOf = (n) => n.buf.subarray(n.start, n.end);
const valOf = (n) => n.buf.subarray(n.vStart, n.vEnd);
function oidOf(n) {
  const b = valOf(n), parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join(".");
}
function parseTime(n) {
  const s = dec.decode(valOf(n));
  const utc = n.tag === 0x17;
  const m = s.match(utc ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/ : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
  if (!m) throw new Error("Bad certificate time: " + s);
  let y = +m[1];
  if (utc) y += y >= 50 ? 1900 : 2000;
  return new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
}
function parseName(n) {
  const o = {};
  for (const rdn of children(n)) for (const atv of children(rdn)) {
    const [k, v] = children(atv);
    o[oidOf(k)] = dec.decode(valOf(v));
  }
  return o;
}
function parseCert(der) {
  const cert = asn1(der);
  const [tbs, sigAlg, sigVal] = children(cert);
  const t = children(tbs);
  let i = 0, version = 1;
  if (t[0].tag === 0xa0) { version = valOf(children(t[0])[0])[0] + 1; i++; }
  i++;                                   // serialNumber
  i++;                                   // signature algorithm (inner)
  const issuer = t[i++], validity = t[i++], subject = t[i++], spki = t[i++];
  const [nb, na] = children(validity);
  const exts = {};
  const extWrap = t.slice(i).find((n) => n.tag === 0xa3);
  if (extWrap) {
    for (const e of children(children(extWrap)[0])) {
      const c = children(e);
      exts[oidOf(c[0])] = valOf(c[c.length - 1]);
    }
  }
  return {
    der, version, exts,
    tbs: rawOf(tbs),
    sig: valOf(sigVal).subarray(1),      // drop "unused bits" byte
    sigAlgOid: oidOf(children(sigAlg)[0]),
    spki: rawOf(spki),
    issuerRaw: rawOf(issuer),
    subjectRaw: rawOf(subject),
    subject: parseName(subject),
    notBefore: parseTime(nb),
    notAfter: parseTime(na),
  };
}

// ---------- signature verification via WebCrypto ----------
const CERT_SIG_ALG = {
  "1.2.840.10045.4.3.2": { kind: "ec", hash: "SHA-256" },
  "1.2.840.10045.4.3.3": { kind: "ec", hash: "SHA-384" },
  "1.2.840.10045.4.3.4": { kind: "ec", hash: "SHA-512" },
  "1.2.840.113549.1.1.11": { kind: "rsa", hash: "SHA-256" },
  "1.2.840.113549.1.1.12": { kind: "rsa", hash: "SHA-384" },
  "1.2.840.113549.1.1.13": { kind: "rsa", hash: "SHA-512" },
  "1.3.101.112": { kind: "ed" },
};
const COSE_ALG = {
  "-7": { kind: "ec", hash: "SHA-256" },
  "-35": { kind: "ec", hash: "SHA-384" },
  "-36": { kind: "ec", hash: "SHA-512" },
  "-257": { kind: "rsa", hash: "SHA-256" },
  "-258": { kind: "rsa", hash: "SHA-384" },
  "-259": { kind: "rsa", hash: "SHA-512" },
  "-8": { kind: "ed" },
};
const CURVES = {
  "1.2.840.10045.3.1.7": { name: "P-256", size: 32 },
  "1.3.132.0.34": { name: "P-384", size: 48 },
  "1.3.132.0.35": { name: "P-521", size: 66 },
};

function derSigToRaw(sig, size) {
  const [r, s] = children(asn1(sig)).map((n) => {
    let v = valOf(n);
    while (v.length > size && v[0] === 0) v = v.subarray(1);
    const o = new Uint8Array(size);
    o.set(v, size - v.length);
    return o;
  });
  return concat(r, s);
}

async function verifySig(spki, alg, data, sig) {
  const s = crypto.subtle;
  if (alg.kind === "ec") {
    const [algId] = children(asn1(spki));
    const curve = CURVES[oidOf(children(algId)[1])];
    if (!curve) throw new Error("Unsupported EC curve");
    const key = await s.importKey("spki", spki, { name: "ECDSA", namedCurve: curve.name }, false, ["verify"]);
    return s.verify({ name: "ECDSA", hash: alg.hash }, key, derSigToRaw(sig, curve.size), data);
  }
  if (alg.kind === "rsa") {
    const key = await s.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: alg.hash }, false, ["verify"]);
    return s.verify("RSASSA-PKCS1-v1_5", key, sig, data);
  }
  if (alg.kind === "ed") {
    const key = await s.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
    return s.verify("Ed25519", key, sig, data);
  }
  throw new Error("Unsupported signature algorithm");
}

// ---------- authenticator data ----------
function parseAuthData(ad) {
  const dv = new DataView(ad.buffer, ad.byteOffset, ad.byteLength);
  const r = { rpIdHash: ad.subarray(0, 32), flags: ad[32], signCount: dv.getUint32(33) };
  if (r.flags & 0x40) {
    r.aaguid = ad.subarray(37, 53);
    const idLen = dv.getUint16(53);
    r.credId = ad.subarray(55, 55 + idLen);
    [r.coseKey] = cborDecode(ad, 55 + idLen);
  }
  return r;
}
const fmtUuid = (b) => {
  const h = hex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};

// ---------- certificate checks ----------
async function checkCerts(certs, fmt, aaguid) {
  const now = new Date();
  certs.forEach((c, i) => {
    if (now < c.notBefore || now > c.notAfter) throw new Error(`x5c[${i}] is outside its validity period`);
  });
  // each cert must be issued (signed) by the next one in x5c
  for (let i = 0; i < certs.length - 1; i++) {
    const c = certs[i], parent = certs[i + 1];
    if (!eq(c.issuerRaw, parent.subjectRaw)) throw new Error(`x5c[${i}] issuer does not match x5c[${i + 1}] subject`);
    const alg = CERT_SIG_ALG[c.sigAlgOid];
    if (!alg) throw new Error("Unsupported cert signature algorithm " + c.sigAlgOid);
    if (!(await verifySig(parent.spki, alg, c.tbs, c.sig))) throw new Error(`x5c[${i}] signature not valid under x5c[${i + 1}]`);
  }
  const leaf = certs[0];
  // basicConstraints: leaf must not be a CA
  if (leaf.exts["2.5.29.19"]) {
    const f = children(asn1(leaf.exts["2.5.29.19"]))[0];
    if (f && f.tag === 0x01 && valOf(f)[0] !== 0) throw new Error("Attestation leaf cert is a CA");
  }
  // id-fido-gen-ce-aaguid extension must match authData AAGUID if present
  const aaguidExt = leaf.exts["1.3.6.1.4.1.45724.1.1.4"];
  if (aaguidExt && !eq(valOf(asn1(aaguidExt)), aaguid)) throw new Error("Cert AAGUID extension != authData AAGUID");
  // packed attestation statement certificate requirements (WebAuthn spec)
  if (fmt === "packed") {
    const s = leaf.subject;
    if (leaf.version !== 3) throw new Error("Leaf cert is not X.509 v3");
    if (s["2.5.4.11"] !== "Authenticator Attestation") throw new Error('Subject OU must be "Authenticator Attestation"');
    if (!s["2.5.4.6"] || !s["2.5.4.10"] || !s["2.5.4.3"]) throw new Error("Subject C/O/CN missing");
  }
}

// ---------- main ----------
async function registerAndVerify() {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const rpId = location.hostname;

      const userid = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: rpId, name: "Attestation test" },
      user: { id: userid, name: "Nitrokey Authenticity Test", displayName: "Nitrokey Authenticity Test" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }, { type: "public-key", alg: -8 }],
      attestation: "direct",
      authenticatorSelection: { authenticatorAttachment: "cross-platform", userVerification: "discouraged" },
      timeout: 120000,
    },
  });

  // 1. clientDataJSON
  const clientDataJSON = new Uint8Array(cred.response.clientDataJSON);
  const cd = JSON.parse(dec.decode(clientDataJSON));
  if (cd.type !== "webauthn.create") throw new Error("Wrong clientData type");
  if (cd.challenge !== b64u(challenge)) throw new Error("Challenge mismatch");
  if (cd.origin !== location.origin) throw new Error("Origin mismatch");
  const clientDataHash = new Uint8Array(await sha256(clientDataJSON));

  // 2. attestation object + authData
  const [att] = cborDecode(new Uint8Array(cred.response.attestationObject));
  const fmt = att.get("fmt"), stmt = att.get("attStmt"), authData = att.get("authData");
  const ad = parseAuthData(authData);
  if (!eq(ad.rpIdHash, new Uint8Array(await sha256(enc.encode(rpId))))) throw new Error("rpIdHash mismatch");
  if (!(ad.flags & 0x01)) throw new Error("User Present flag not set");
  if (!ad.aaguid) throw new Error("No attested credential data");

  const x5c = stmt.get("x5c");
  if (!x5c || !x5c.length) throw new Error(`No x5c certificate (fmt=${fmt}); nothing to verify`);
  const certs = x5c.map(parseCert);

  // 3. attestation signature (made by the leaf cert's key)
  let signedData, alg;
  if (fmt === "packed") {
    alg = COSE_ALG[stmt.get("alg")];
    signedData = concat(authData, clientDataHash);
  } else if (fmt === "fido-u2f") {
    const x = ad.coseKey.get(-2), y = ad.coseKey.get(-3);
    alg = COSE_ALG["-7"];
    signedData = concat(new Uint8Array([0]), ad.rpIdHash, clientDataHash, ad.credId, new Uint8Array([4]), x, y);
  } else {
    throw new Error("Unsupported attestation format: " + fmt);
  }
  if (!alg) throw new Error("Unsupported attestation alg " + stmt.get("alg"));
  if (!(await verifySig(certs[0].spki, alg, signedData, stmt.get("sig")))) throw new Error("Attestation signature is INVALID");

  // 4. certificate checks
  await checkCerts(certs, fmt, ad.aaguid);

  // 5. success: print results
  const cert = hex(await sha256(certs[0].der))
  console.log("First attestation cert SHA-256:", cert);
  console.log("AAGUID:", fmtUuid(ad.aaguid));
  return cert
  
}

