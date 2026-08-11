"use strict";
/**
 * Everything the process reads from its environment, in one place.
 *
 * Scattered `process.env` reads make it impossible to answer "what does this
 * node do" without grepping, and — more practically — impossible to run two
 * nodes in one test process.  Configuration is resolved once, into a value.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadConfig = loadConfig;
exports.checkConfiguration = checkConfiguration;
function loadConfig(env = process.env) {
    const num = (name, fallback) => {
        const raw = env[name];
        if (raw === undefined || raw === '')
            return fallback;
        const value = Number(raw);
        return Number.isFinite(value) && value >= 0 ? value : fallback;
    };
    const bool = (name, fallback) => {
        const raw = env[name];
        if (raw === undefined || raw === '')
            return fallback;
        return raw === 'true' || raw === '1' || raw === 'yes';
    };
    const list = (name) => (env[name] ?? '')
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
    const local = bool('TRUST_LOCAL', false);
    const port = num('PORT', local ? 8090 : 8080);
    return {
        port,
        publicUrl: (env.PUBLIC_URL ?? (local ? `http://127.0.0.1:${port}` : '')).replace(/\/+$/, ''),
        appUrl: (env.APP_URL ?? '').replace(/\/+$/, ''),
        name: env.NODE_NAME ?? (local ? 'local' : ''),
        local,
        store: env.STORE ?? (local ? 'sqlite' : 'pg'),
        databaseUrl: env.DATABASE_URL ?? '',
        sqlitePath: env.SQLITE_PATH ?? defaultSqlitePath(env),
        // In local mode nothing is exposed and there is nobody to forge a session
        // against, so a generated secret beats refusing to start over a missing one.
        sessionSecret: env.SESSION_SECRET ?? '',
        cookieSecure: bool('COOKIE_SECURE', false),
        github: { clientId: env.GITHUB_CLIENT_ID ?? '', clientSecret: env.GITHUB_CLIENT_SECRET ?? '' },
        seeds: list('FEDERATION_SEEDS'),
        adminToken: env.ADMIN_TOKEN ?? '',
        policy: {
            maxDepth: num('FEDERATION_MAX_DEPTH', 2),
            maxEntries: num('FEDERATION_MAX_ENTRIES', 500),
            maxResponseBytes: num('FEDERATION_MAX_RESPONSE_BYTES', 2 * 1024 * 1024),
            peerTimeoutMs: num('FEDERATION_PEER_TIMEOUT_MS', 4000),
            queryBudgetMs: num('FEDERATION_QUERY_BUDGET_MS', 8000),
            remoteTtlS: num('FEDERATION_REMOTE_TTL_S', 300),
            maxViaLength: num('FEDERATION_MAX_VIA', 8),
            autodiscover: bool('FEDERATION_AUTODISCOVER', false),
            // Local mode pulls from other things on the same machine, so the private
            // address rule would forbid exactly its normal use.  A public deployment
            // has to opt in deliberately.
            allowPrivate: bool('FEDERATION_ALLOW_PRIVATE', local),
        },
    };
}
/** `~/.local/share/trust/trust.db`, or `$XDG_DATA_HOME` when it is set. */
function defaultSqlitePath(env) {
    const base = env.XDG_DATA_HOME || (env.HOME ? `${env.HOME}/.local/share` : '.');
    return `${base}/trust/trust.db`;
}
/**
 * Refuse to start misconfigured rather than fail confusingly on first use.
 *
 * Local mode needs almost none of this: there is no OAuth round trip to get
 * wrong and no origin to mismatch, and demanding a GitHub app before someone
 * can keep their own judgements in their own database would be absurd.
 */
function checkConfiguration(config) {
    const problems = [];
    if (config.store === 'pg' && !config.databaseUrl)
        problems.push('DATABASE_URL is not set');
    if (!config.local) {
        if (config.sessionSecret.length < 32) {
            problems.push('SESSION_SECRET must be at least 32 characters (openssl rand -hex 32)');
        }
        if (!config.github.clientId)
            problems.push('GITHUB_CLIENT_ID is not set');
        if (!config.github.clientSecret)
            problems.push('GITHUB_CLIENT_SECRET is not set');
        if (!config.publicUrl)
            problems.push('PUBLIC_URL is not set');
    }
    if (config.publicUrl && !/^https?:\/\//.test(config.publicUrl)) {
        problems.push('PUBLIC_URL must be an absolute http(s) URL');
    }
    return problems;
}
