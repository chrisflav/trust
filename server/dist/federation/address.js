"use strict";
/**
 * Which addresses this node is willing to talk to.
 *
 * A peer URL is attacker-supplied input: anyone may announce one (§5.2), and
 * every node hands its peers' URLs to every other node.  Without this file, a
 * federating server is a machine that will issue HTTP requests to any address
 * on its own network on a stranger's instruction, which is a more useful thing
 * to an attacker than anything the trust database itself contains.
 *
 * The classification is kept pure so it can be tested exhaustively; only
 * `checkPeerUrl` touches DNS.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeUrl = normalizeUrl;
exports.isBlockedAddress = isBlockedAddress;
exports.checkPeerUrl = checkPeerUrl;
const node_net_1 = require("node:net");
const promises_1 = require("node:dns/promises");
/** Normalise for comparison: a peer is one node however its URL is written. */
function normalizeUrl(raw, options = {}) {
    let url;
    try {
        url = new URL(raw);
    }
    catch {
        return { error: 'not a URL' };
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        return { error: `unsupported scheme ${url.protocol}` };
    }
    // Credentials would be sent to whatever the name resolves to, and a fragment
    // never reaches a server at all — both are likelier to be an attempt at
    // something than a typo.
    if (url.username || url.password)
        return { error: 'a peer URL must carry no credentials' };
    if (url.hash)
        return { error: 'a peer URL must carry no fragment' };
    if (url.search && !options.allowQuery)
        return { error: 'a peer URL must carry no query' };
    const path = url.pathname.replace(/\/+$/, '');
    return `${url.protocol}//${url.host.toLowerCase()}${path}${options.allowQuery ? url.search : ''}`;
}
/** Expand any IPv6 text into its eight groups, or null if it is not one. */
function expandIPv6(address) {
    const text = address.replace(/^\[|\]$/g, '').toLowerCase();
    if ((0, node_net_1.isIP)(text) !== 6)
        return null;
    const [head, tail] = text.split('::');
    const parse = (part) => (part.length === 0 ? [] : part.split(':'));
    const left = parse(head ?? '');
    const right = tail === undefined ? [] : parse(tail);
    // A trailing IPv4 form (`::ffff:127.0.0.1`) occupies the last two groups.
    const groups = [];
    const push = (part) => {
        if (part.includes('.')) {
            const octets = part.split('.').map(Number);
            groups.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
        }
        else {
            groups.push(parseInt(part, 16));
        }
    };
    for (const part of left)
        push(part);
    const filled = groups.length;
    const tailGroups = [];
    for (const part of right) {
        const before = groups.length;
        push(part);
        tailGroups.push(...groups.slice(before));
        groups.length = before;
    }
    if (tail === undefined)
        return filled === 8 ? groups : null;
    const zeros = 8 - filled - tailGroups.length;
    if (zeros < 0)
        return null;
    return [...groups, ...Array(zeros).fill(0), ...tailGroups];
}
/**
 * Is this address one a public node must refuse to contact?
 *
 * Everything not routable on the public internet is refused, not merely
 * loopback: the interesting targets on a server's network are its neighbours
 * and its cloud metadata service, none of which are on `127.0.0.0/8`.
 */
function isBlockedAddress(address) {
    const family = (0, node_net_1.isIP)(address);
    if (family === 4)
        return isBlockedIPv4(address.split('.').map(Number));
    if (family === 6) {
        const groups = expandIPv6(address);
        if (!groups)
            return true;
        // IPv4-mapped and IPv4-compatible forms are the same addresses wearing a
        // hat; classify them as what they are rather than as v6.
        const mapped = groups.slice(0, 5).every((group) => group === 0) &&
            (groups[5] === 0xffff || groups[5] === 0);
        if (mapped && !(groups[6] === 0 && groups[7] === 0)) {
            return isBlockedIPv4([groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff]);
        }
        if (groups.every((group) => group === 0))
            return true; // ::
        if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1)
            return true; // ::1
        if ((groups[0] & 0xfe00) === 0xfc00)
            return true; // fc00::/7  unique local
        if ((groups[0] & 0xffc0) === 0xfe80)
            return true; // fe80::/10 link local
        if ((groups[0] & 0xff00) === 0xff00)
            return true; // ff00::/8  multicast
        return false;
    }
    return true;
}
function isBlockedIPv4([a, b]) {
    if (a === 0)
        return true; // 0.0.0.0/8    this network
    if (a === 10)
        return true; // 10.0.0.0/8   private
    if (a === 127)
        return true; // 127.0.0.0/8  loopback
    if (a === 169 && b === 254)
        return true; // link local, and the metadata service
    if (a === 172 && b >= 16 && b <= 31)
        return true; // 172.16.0.0/12 private
    if (a === 192 && b === 168)
        return true; // 192.168.0.0/16 private
    if (a === 192 && b === 0)
        return true; // 192.0.0.0/24 protocol assignments
    if (a === 100 && b >= 64 && b <= 127)
        return true; // 100.64.0.0/10 carrier NAT
    if (a === 198 && (b === 18 || b === 19))
        return true; // 198.18.0.0/15 benchmarking
    if (a >= 224)
        return true; // multicast and reserved
    return false;
}
/**
 * Everything §5.4 requires, in the order that fails cheapest first.
 *
 * `allowPrivate` turns the address rule off wholesale.  That is right for local
 * mode, where "the other database" is usually on the same machine, and wrong
 * for anything reachable from outside — which is why it is not the default and
 * why the two are separate switches rather than one "dev mode".
 */
async function checkPeerUrl(raw, policy, options = {}) {
    const normalized = normalizeUrl(raw, options);
    if (typeof normalized !== 'string')
        return normalized;
    const url = new URL(normalized);
    if (url.protocol === 'http:' && !policy.allowPrivate) {
        return { error: 'a peer must be reachable over https' };
    }
    if (policy.allowPrivate)
        return { url: normalized, addresses: [] };
    const host = url.hostname.replace(/^\[|\]$/g, '');
    // A literal address never reaches the resolver, so it has to be checked here
    // or `http://127.0.0.1/` walks straight through.
    if ((0, node_net_1.isIP)(host)) {
        if (isBlockedAddress(host))
            return { error: `refusing a non-public address (${host})` };
        return { url: normalized, addresses: [host] };
    }
    let resolved;
    try {
        resolved = await (0, promises_1.lookup)(host, { all: true });
    }
    catch {
        return { error: `cannot resolve ${host}` };
    }
    if (resolved.length === 0)
        return { error: `cannot resolve ${host}` };
    for (const { address } of resolved) {
        // Every answer must be public.  A name with one public and one private
        // address is not half-safe; it is a way of asking for the private one.
        if (isBlockedAddress(address)) {
            return { error: `${host} resolves to a non-public address (${address})` };
        }
    }
    return { url: normalized, addresses: resolved.map((entry) => entry.address) };
}
