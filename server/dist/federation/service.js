"use strict";
/**
 * Federation as the server performs it: importing, pulling, and answering a
 * question that this node cannot answer alone.
 *
 * `protocol.ts` decides what may be believed; this decides who to ask and what
 * to do with the answer.  Keeping them apart matters because the first is pure
 * and exhaustively tested, and the second is full of timeouts and peers that
 * behave badly.
 */
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
exports.parseCursor = void 0;
exports.importBundle = importBundle;
exports.toEntry = toEntry;
exports.pullFrom = pullFrom;
exports.pullFromAll = pullFromAll;
exports.answer = answer;
exports.announcePeer = announcePeer;
exports.discoverThrough = discoverThrough;
exports.descriptorFor = descriptorFor;
const certificate_1 = require("../certificate");
const client_1 = require("./client");
const protocol_1 = require("./protocol");
Object.defineProperty(exports, "parseCursor", { enumerable: true, get: function () { return protocol_1.parseCursor; } });
const address_1 = require("./address");
/**
 * Take a bundle apart and keep what survives §3.4.
 *
 * Entries are checked one at a time and a bad one costs only itself: a peer
 * that sends one forgery among a hundred honest entries has sent ninety-nine
 * honest entries, and dropping the lot would let anyone deny service to a node
 * by poisoning somebody else's export.
 */
async function importBundle(store, bundle, fromPeer) {
    const report = { accepted: 0, rejected: 0, revocations: 0, reasons: [] };
    const now = Date.now();
    for (const raw of bundle.entries) {
        const entry = await (0, protocol_1.acceptEntry)(raw);
        if ('error' in entry) {
            report.rejected++;
            if (report.reasons.length < 10 && !report.reasons.includes(entry.error)) {
                report.reasons.push(entry.error);
            }
            continue;
        }
        if (!entry.hints?.origin && bundle.origin) {
            entry.hints = { ...entry.hints, origin: bundle.origin };
        }
        await store.upsertRemote(entry, fromPeer, now);
        report.accepted++;
    }
    for (const raw of bundle.revocations) {
        const revocation = await (0, protocol_1.acceptRevocation)(raw);
        if ('error' in revocation) {
            report.rejected++;
            if (report.reasons.length < 10 && !report.reasons.includes(revocation.error)) {
                report.reasons.push(revocation.error);
            }
            continue;
        }
        await store.upsertRevocation(revocation);
        report.revocations++;
    }
    return report;
}
/** A local signed certificate, in the shape it travels in. */
function toEntry(certificate, origin) {
    if (!certificate.signature || !certificate.fingerprint || !certificate.armoredKey)
        return null;
    return {
        claim: certificate.claim,
        signature: certificate.signature,
        key: certificate.armoredKey,
        fingerprint: certificate.fingerprint,
        hints: {
            issuer: certificate.issuer,
            keyVerifiedVia: certificate.keyVerifiedVia ?? 'self',
            origin,
        },
    };
}
/**
 * Catch up with one peer, following its cursor until it says it is complete.
 *
 * Bounded by `rounds` as well as by the peer's own honesty: a node that always
 * answers `complete: false` with the same cursor would otherwise be an infinite
 * loop, and it costs nothing to assume somebody will eventually be that node.
 */
async function pullFrom(store, config, peerUrl, rounds = 20) {
    const options = { policy: config.policy };
    const report = { peer: peerUrl, ok: true, accepted: 0, rejected: 0 };
    const peer = await store.peerByUrl(peerUrl);
    let cursor = peer?.cursor || undefined;
    for (let round = 0; round < rounds; round++) {
        const bundle = await (0, client_1.fetchBundle)(peerUrl, cursor, options);
        if ('error' in bundle) {
            report.ok = false;
            report.error = bundle.error;
            await store.notePeerSeen(peerUrl, cursor ?? '', bundle.error);
            return report;
        }
        const imported = await importBundle(store, bundle, peerUrl);
        report.accepted += imported.accepted;
        report.rejected += imported.rejected;
        const next = bundle.cursor;
        // No forward progress means there is nothing more to have, whatever the
        // peer says about completeness.
        if (!next || next === cursor)
            break;
        cursor = next;
        await store.notePeerSeen(peerUrl, cursor, '');
        if (bundle.complete)
            break;
    }
    await store.notePeerSeen(peerUrl, cursor ?? '', '');
    return report;
}
/** Catch up with everyone worth asking, one at a time to stay polite. */
async function pullFromAll(store, config) {
    const peers = await store.listPeers(['seed', 'active']);
    const reports = [];
    for (const peer of peers)
        reports.push(await pullFrom(store, config, peer.url));
    return reports;
}
/**
 * Answer from here, from the cache, and — if depth allows — from peers.
 *
 * The fan-out runs under one wall-clock budget rather than a peer count: a
 * reader waiting on "who trusts this" should not discover how many peers the
 * operator configured, or that one of them is down.
 */
async function answer(store, config, question) {
    const { policy } = config;
    const filter = {
        hash: question.hash,
        hasher: question.hasher,
        fingerprint: question.fingerprint,
    };
    let truncated = false;
    let askedPeers = 0;
    const relayable = Math.min(question.depth, policy.maxDepth);
    const self = config.publicUrl ? (0, address_1.normalizeUrl)(config.publicUrl) : '';
    const me = typeof self === 'string' ? self : '';
    // A node that finds itself in the chain has already answered this question;
    // going round again would only multiply it.
    const alreadyVisited = me.length > 0 && question.via.includes(me);
    if (relayable > 0 && !alreadyVisited) {
        const fresh = await store.remoteFreshness(filter);
        const stale = Date.now() - fresh > policy.remoteTtlS * 1000;
        if (stale) {
            const result = await fanOut(store, config, question, relayable, me);
            truncated = result.truncated;
            askedPeers = result.asked;
        }
    }
    const [local, remote, revocations] = await Promise.all([
        store.localCertificates(filter),
        store.remoteCertificates(filter),
        store.revocations(filter),
    ]);
    const certificates = [];
    for (const certificate of local) {
        if ((0, protocol_1.isSuppressed)({ fingerprint: certificate.fingerprint ?? '', claim: certificate.claim }, revocations)) {
            continue;
        }
        certificates.push({
            claim: certificate.claim,
            canonical: (0, certificate_1.canonicalClaim)(certificate.claim),
            signature: certificate.signature,
            key: certificate.armoredKey,
            fingerprint: certificate.fingerprint,
            assurance: certificate.assurance,
            issuer: certificate.issuer,
            avatarUrl: certificate.avatarUrl,
            keyVerifiedVia: certificate.keyVerifiedVia,
            provenance: {
                local: true,
                origin: me,
                fromPeer: '',
                verifiedHere: certificate.assurance === 'signed',
                fetchedAt: null,
            },
        });
    }
    const seen = new Set(certificates
        .filter((certificate) => certificate.fingerprint)
        .map((certificate) => `${certificate.fingerprint} ${certificate.claim.hash} ${certificate.claim.hasher}`));
    for (const certificate of remote) {
        const key = `${certificate.fingerprint} ${certificate.claim.hash} ${certificate.claim.hasher}`;
        // A locally-issued certificate wins over the same one heard second-hand:
        // identical content, but this node knows more about where it came from.
        if (seen.has(key))
            continue;
        if ((0, protocol_1.isSuppressed)(certificate, revocations))
            continue;
        certificates.push({
            claim: certificate.claim,
            canonical: (0, certificate_1.canonicalClaim)(certificate.claim),
            signature: certificate.signature,
            key: certificate.armoredKey,
            fingerprint: certificate.fingerprint,
            assurance: 'signed',
            issuer: certificate.hints.issuer ?? '',
            avatarUrl: '',
            keyVerifiedVia: certificate.hints.keyVerifiedVia ?? null,
            provenance: {
                local: false,
                origin: certificate.hints.origin ?? '',
                fromPeer: certificate.fromPeer,
                verifiedHere: true,
                fetchedAt: new Date(certificate.fetchedMs).toISOString(),
            },
        });
    }
    certificates.sort((a, b) => {
        if (a.assurance !== b.assurance)
            return a.assurance === 'signed' ? -1 : 1;
        return Date.parse(b.claim.asserted) - Date.parse(a.claim.asserted);
    });
    return { certificates, truncated, askedPeers };
}
async function fanOut(store, config, question, depth, me) {
    const peers = await store.listPeers(['seed', 'active']);
    const via = [...question.via, ...(me ? [me] : [])].slice(0, config.policy.maxViaLength);
    const targets = peers.filter((peer) => !question.via.includes(peer.url) && peer.url !== me);
    if (targets.length === 0)
        return { truncated: false, asked: 0 };
    const budget = AbortSignal.timeout(config.policy.queryBudgetMs);
    const results = await Promise.allSettled(targets.map(async (peer) => {
        const bundle = await (0, client_1.queryPeer)(peer.url, {
            hash: question.hash,
            hasher: question.hasher,
            fingerprint: question.fingerprint,
            depth: depth - 1,
            via,
        }, { policy: config.policy, signal: budget });
        if ('error' in bundle)
            throw new Error(bundle.error);
        await importBundle(store, bundle, peer.url);
        return bundle.complete;
    }));
    // Anything that did not come back means the answer might be short, and a
    // short answer presented as complete is the one failure mode that matters:
    // "nobody trusts this" and "I could not find out" are different sentences.
    const truncated = results.some((result) => result.status === 'rejected' || result.value === false);
    return { truncated, asked: targets.length };
}
/**
 * Record a node that has announced itself.
 *
 * The descriptor is fetched and its `url` must match what was announced.  That
 * single check is what stops this endpoint being a scanner: only a host that
 * actually runs a node, and knows its own name, can be announced through it.
 */
async function announcePeer(store, config, announced) {
    const normalized = (0, address_1.normalizeUrl)(announced);
    if (typeof normalized !== 'string')
        return normalized;
    const existing = await store.peerByUrl(normalized);
    if (existing?.status === 'blocked')
        return { error: 'that node is blocked here' };
    const descriptor = await (0, client_1.fetchDescriptor)(normalized, { policy: config.policy });
    if ('error' in descriptor)
        return { error: descriptor.error };
    const claimed = (0, address_1.normalizeUrl)(descriptor.url);
    if (typeof claimed !== 'string' || claimed !== normalized) {
        return { error: 'that node calls itself something else; refusing to record it' };
    }
    // Discovery proposes; only the operator promotes.  `autodiscover` is the
    // operator saying in advance that they are content to be proposed to.
    const status = existing?.status ?? (config.policy.autodiscover ? 'active' : 'candidate');
    await store.upsertPeer(normalized, descriptor.name, status);
    return { url: normalized, name: descriptor.name, status };
}
/**
 * Learn about a peer's peers.
 *
 * Recorded as candidates whatever the sender says, because the sender's opinion
 * of who is worth talking to is not this operator's.
 */
async function discoverThrough(store, config, peerUrl) {
    const body = await fetchJsonPeers(config, peerUrl);
    if (!body)
        return 0;
    let learned = 0;
    for (const url of body.slice(0, 100)) {
        const normalized = (0, address_1.normalizeUrl)(url);
        if (typeof normalized !== 'string')
            continue;
        if (normalized === peerUrl)
            continue;
        if (await store.peerByUrl(normalized))
            continue;
        const result = await announcePeer(store, config, normalized);
        if (!('error' in result))
            learned++;
    }
    return learned;
}
async function fetchJsonPeers(config, peerUrl) {
    const { fetchJson } = await Promise.resolve().then(() => __importStar(require('./client')));
    const body = await fetchJson(`${peerUrl}/api/peers`, { policy: config.policy });
    if (!body || typeof body !== 'object' || 'error' in body)
        return null;
    const peers = body.peers;
    if (!Array.isArray(peers))
        return null;
    return peers
        .map((peer) => (typeof peer === 'object' && peer !== null ? peer.url : null))
        .filter((url) => typeof url === 'string');
}
function descriptorFor(config, counts) {
    return {
        protocol: protocol_1.PROTOCOL,
        url: config.publicUrl,
        name: config.name || (config.publicUrl ? new URL(config.publicUrl).host : 'trust'),
        software: 'trust-server/0.2.0',
        policy: {
            maxDepth: config.policy.maxDepth,
            maxEntries: config.policy.maxEntries,
            autodiscover: config.policy.autodiscover,
        },
        counts,
    };
}
