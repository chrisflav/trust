"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.canonicalClaim = canonicalClaim;
exports.parseClaim = parseClaim;
exports.canonicalRevocation = canonicalRevocation;
exports.parseRevocation = parseRevocation;
exports.verifyDetached = verifyDetached;
exports.verifySignature = verifySignature;
exports.readPublicKey = readPublicKey;
const openpgp = __importStar(require("openpgp"));
const CLAIM_FIELDS = [
    'asserted',
    'commit',
    'decl',
    'hash',
    'hasher',
    'note',
    'repo',
    'toolchain',
];
/**
 * The exact bytes a signature is made over.
 *
 * Fields in a fixed order with no incidental whitespace, so that a claim
 * re-serialised anywhere — this server, the CLI, a reader checking by hand —
 * produces the identical string.  Anything less rigid and a signature would
 * verify on the machine that made it and nowhere else.
 */
function canonicalClaim(claim) {
    const parts = CLAIM_FIELDS.map((field) => `${JSON.stringify(field)}:${JSON.stringify(claim[field])}`);
    return `{${parts.join(',')}}`;
}
/** Reject anything that is not a well-formed claim before it reaches the database. */
function parseClaim(value) {
    if (typeof value !== 'object' || value === null)
        return { error: 'claim must be an object' };
    const raw = value;
    const out = {};
    for (const field of CLAIM_FIELDS) {
        const got = raw[field];
        if (field === 'note') {
            out[field] = typeof got === 'string' ? got : '';
            continue;
        }
        if (typeof got !== 'string' || got.length === 0)
            return { error: `claim.${field} is required` };
        out[field] = got;
    }
    if (!/^[0-9a-f]{16,128}$/.test(out.hash)) {
        return { error: 'claim.hash must be lower-case hex' };
    }
    if (Number.isNaN(Date.parse(out.asserted)))
        return { error: 'claim.asserted must be a timestamp' };
    return out;
}
const REVOCATION_FIELDS = [
    'fingerprint',
    'hash',
    'hasher',
    'reason',
    'revoked',
];
/** The bytes a revocation's signature covers.  Same rules as `canonicalClaim`. */
function canonicalRevocation(revocation) {
    const parts = REVOCATION_FIELDS.map((field) => `${JSON.stringify(field)}:${JSON.stringify(revocation[field])}`);
    return `{${parts.join(',')}}`;
}
function parseRevocation(value) {
    if (typeof value !== 'object' || value === null)
        return { error: 'revocation must be an object' };
    const raw = value;
    const out = {};
    for (const field of REVOCATION_FIELDS) {
        const got = raw[field];
        if (field === 'reason') {
            out[field] = typeof got === 'string' ? got : '';
            continue;
        }
        if (typeof got !== 'string' || got.length === 0)
            return { error: `revocation.${field} is required` };
        out[field] = got;
    }
    if (!/^[0-9a-f]{16,128}$/.test(out.hash))
        return { error: 'revocation.hash must be lower-case hex' };
    if (!/^[0-9a-fA-F]{16,64}$/.test(out.fingerprint)) {
        return { error: 'revocation.fingerprint must be hex' };
    }
    out.fingerprint = out.fingerprint.toLowerCase();
    if (Number.isNaN(Date.parse(out.revoked)))
        return { error: 'revocation.revoked must be a timestamp' };
    return out;
}
/**
 * Check a detached signature over `text` against a set of public keys.
 *
 * The server does this so it can store the verdict and answer "who trusts
 * this" quickly — but it stores it as a *cache*, and hands back everything a
 * client needs to repeat the check itself.  A tool whose subject is trust
 * should not ask to be taken at its word, and a compromised server that can
 * fabricate `attested` rows still cannot forge one of these.
 *
 * The signing key has to be *identified*, not merely present: openpgp will
 * confirm a signature against a bundle without saying which key in it signed,
 * and a verdict that cannot name the key is useless for attributing anything.
 * So a signature whose key is not among those offered is a failure here, even
 * though the cryptography succeeded.
 */
async function verifyDetached(text, armoredSignature, armoredKeys) {
    if (armoredKeys.length === 0)
        return { ok: false, reason: 'no public key to check against' };
    try {
        const message = await openpgp.createMessage({ text });
        const signature = await openpgp.readSignature({ armoredSignature });
        const keys = await Promise.all(armoredKeys.map((armoredKey) => openpgp.readKey({ armoredKey })));
        const result = await openpgp.verify({ message, signature, verificationKeys: keys });
        const check = result.signatures[0];
        if (!check)
            return { ok: false, reason: 'no signature found' };
        await check.verified;
        const keyID = check.keyID.toHex();
        const key = keys.find((candidate) => candidate.getKeys().some((sub) => sub.getKeyID().toHex() === keyID));
        if (!key)
            return { ok: false, reason: 'signature is not from any of the offered keys' };
        return { ok: true, fingerprint: key.getFingerprint().toLowerCase() };
    }
    catch (error) {
        return { ok: false, reason: String(error instanceof Error ? error.message : error) };
    }
}
function verifySignature(claim, armoredSignature, armoredKeys) {
    return verifyDetached(canonicalClaim(claim), armoredSignature, armoredKeys);
}
/**
 * Read an armored public key, refusing a private one.
 *
 * A private key block parses perfectly well as a key, so "it loaded" is not the
 * check.  Nothing in this server has any use for signing material, and the way
 * to guarantee it never leaks it is to never hold it.
 */
async function readPublicKey(armored) {
    if (typeof armored !== 'string')
        return { error: 'expected an armored PGP public key' };
    // Checked before the public-key check so that someone who pastes the wrong
    // half is told what they actually did, rather than that it is not a key.
    if (armored.includes('PRIVATE KEY BLOCK')) {
        return { error: 'that is a private key — never send one here' };
    }
    if (!armored.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
        return { error: 'expected an armored PGP public key' };
    }
    try {
        const key = await openpgp.readKey({ armoredKey: armored });
        if (key.isPrivate())
            return { error: 'that is a private key — never send one here' };
        return { fingerprint: key.getFingerprint().toLowerCase() };
    }
    catch (error) {
        return { error: `unreadable key: ${String(error instanceof Error ? error.message : error)}` };
    }
}
