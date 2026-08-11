"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashToken = hashToken;
exports.newToken = newToken;
exports.createAuth = createAuth;
const node_crypto_1 = require("node:crypto");
/**
 * Sessions as a signed cookie.
 *
 * The only thing a session has to carry is which identity you are, so a signed
 * cookie does it without a session store or a dependency.  It is signed, not
 * encrypted: the identity id is not a secret, and tampering is what matters.
 *
 * Built as a value rather than a module of globals, so that two nodes can run
 * in one process — which is how the federation between them gets tested.
 */
const COOKIE = 'trust_session';
/** Hash a token the way it is stored, so the plaintext is never persisted. */
function hashToken(token) {
    return (0, node_crypto_1.createHash)('sha256').update(token).digest('hex');
}
function newToken() {
    return `trust_${(0, node_crypto_1.randomBytes)(24).toString('base64url')}`;
}
function createAuth(config, store) {
    // Local mode has no public surface and one user; refusing to start over a
    // missing secret would be ceremony, and a random one per process is strictly
    // safer than a default anybody could look up.
    const secret = config.sessionSecret.length >= 32 ? config.sessionSecret : (0, node_crypto_1.randomBytes)(32).toString('hex');
    const sign = (value) => (0, node_crypto_1.createHmac)('sha256', secret).update(value).digest('base64url');
    const pendingStates = new Map();
    const readSession = (request) => {
        const raw = request.headers.cookie
            ?.split(';')
            .map((part) => part.trim())
            .find((part) => part.startsWith(`${COOKIE}=`))
            ?.slice(COOKIE.length + 1);
        if (!raw)
            return null;
        const dot = raw.lastIndexOf('.');
        if (dot < 0)
            return null;
        const payload = raw.slice(0, dot);
        const provided = Buffer.from(raw.slice(dot + 1));
        const expected = Buffer.from(sign(payload));
        // Constant-time, so the comparison cannot be used to guess a valid signature.
        if (provided.length !== expected.length || !(0, node_crypto_1.timingSafeEqual)(provided, expected))
            return null;
        try {
            return JSON.parse(Buffer.from(payload, 'base64url').toString());
        }
        catch {
            return null;
        }
    };
    /** Resolve a `Authorization: Bearer` token to the identity that owns it. */
    const userFromToken = async (header) => {
        const token = header.slice('Bearer '.length).trim();
        if (token.length === 0)
            return null;
        return store.identityForToken(hashToken(token));
    };
    /**
     * Accept a browser session, a command-line token, or — in local mode — the
     * fact that there is only one person this database could mean.
     *
     * The CLI cannot hold a cookie session, and pushing people through a browser
     * to publish something they just signed locally would make signing the
     * awkward path rather than the normal one.
     */
    const requireUser = async (request, response, next) => {
        const header = request.headers.authorization;
        let user = header?.startsWith('Bearer ') ? await userFromToken(header) : readSession(request);
        if (!user && config.local)
            user = await store.ensureLocalIdentity(config.name || 'local');
        if (!user) {
            response.status(401).json({ error: 'sign in with GitHub, or send a Bearer token' });
            return;
        }
        ;
        request.user = user;
        next();
    };
    return {
        issueSession(response, user) {
            const payload = Buffer.from(JSON.stringify(user)).toString('base64url');
            response.cookie(COOKIE, `${payload}.${sign(payload)}`, {
                httpOnly: true,
                sameSite: 'lax',
                secure: config.cookieSecure,
                maxAge: 30 * 24 * 60 * 60 * 1000,
            });
        },
        readSession,
        requireUser,
        currentUser(request) {
            return request.user;
        },
        /** Short-lived anti-forgery state for the OAuth round trip. */
        newState() {
            const state = (0, node_crypto_1.randomBytes)(16).toString('hex');
            pendingStates.set(state, Date.now());
            for (const [key, at] of pendingStates) {
                if (Date.now() - at > 10 * 60 * 1000)
                    pendingStates.delete(key);
            }
            return state;
        },
        consumeState(state) {
            return pendingStates.delete(state);
        },
        authorizeUrl() {
            const redirect = new URL('https://github.com/login/oauth/authorize');
            redirect.searchParams.set('client_id', config.github.clientId);
            redirect.searchParams.set('redirect_uri', `${config.publicUrl}/auth/github/callback`);
            redirect.searchParams.set('scope', 'read:user');
            redirect.searchParams.set('state', this.newState());
            return redirect.toString();
        },
        async exchangeCode(code) {
            const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({
                    client_id: config.github.clientId,
                    client_secret: config.github.clientSecret,
                    code,
                }),
            });
            const token = (await tokenResponse.json());
            if (!token.access_token)
                throw new Error(token.error ?? 'GitHub did not return a token');
            const userResponse = await fetch('https://api.github.com/user', {
                headers: { Authorization: `Bearer ${token.access_token}`, Accept: 'application/vnd.github+json' },
            });
            if (!userResponse.ok)
                throw new Error(`GitHub user lookup failed: ${userResponse.status}`);
            return (await userResponse.json());
        },
        /**
         * The public keys GitHub itself publishes for an account.
         *
         * Used to mark a key `github` rather than `self`: it ties a fingerprint to
         * an account through a party that is not us, which is a materially stronger
         * claim than "someone pasted this here while signed in".
         */
        async githubPublicKeys(login) {
            try {
                const response = await fetch(`https://api.github.com/users/${encodeURIComponent(login)}/gpg_keys`, { headers: { Accept: 'application/vnd.github+json' } });
                if (!response.ok)
                    return [];
                const keys = (await response.json());
                return keys.map((key) => key.raw_key ?? '').filter((key) => key.length > 0);
            }
            catch {
                return [];
            }
        },
        hashToken,
        newToken,
    };
}
