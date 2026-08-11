"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApp = createApp;
exports.openStore = openStore;
const express_1 = __importDefault(require("express"));
const config_1 = require("./config");
const auth_1 = require("./auth");
const routes_1 = require("./routes");
const db_1 = require("./store/db");
const store_1 = require("./store");
const service_1 = require("./federation/service");
/**
 * Paths any node may read, from anywhere, without a session.
 *
 * Everything they return is either public by construction or signed, so the
 * useful CORS answer is `*` — and `*` is only usable *because* they need no
 * credentials.  The rest of the API keeps the single named origin it has
 * always had, since `*` and cookies are mutually exclusive for good reason.
 */
const PUBLIC_PREFIXES = ['/api/federation', '/api/peers', '/api/certificates', '/api/key'];
function isPublicRead(request) {
    return (request.method === 'GET' &&
        PUBLIC_PREFIXES.some((prefix) => request.path === prefix || request.path.startsWith(`${prefix}/`)));
}
function createApp(config, store) {
    const app = (0, express_1.default)();
    app.use(express_1.default.json({ limit: '1mb' }));
    app.use((request, response, next) => {
        if (isPublicRead(request)) {
            response.setHeader('Access-Control-Allow-Origin', '*');
        }
        else if (config.appUrl) {
            response.setHeader('Access-Control-Allow-Origin', config.appUrl);
            response.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        response.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
        if (request.method === 'OPTIONS') {
            response.status(204).end();
            return;
        }
        next();
    });
    app.use((0, routes_1.createRoutes)(config, store, (0, auth_1.createAuth)(config, store)));
    app.use((error, _req, res, _next) => {
        console.error(error);
        res.status(500).json({ error: 'internal error' });
    });
    return app;
}
async function openStore(config) {
    const db = await (0, db_1.openDb)({
        kind: config.store,
        connectionString: config.databaseUrl,
        path: config.sqlitePath,
    });
    if (config.store === 'pg')
        await (0, db_1.waitForDatabase)(db);
    const store = new store_1.Store(db);
    await store.ready();
    return store;
}
/** Record the peers the operator configured, without ever querying them yet. */
async function adoptSeeds(config, store) {
    for (const seed of config.seeds) {
        const existing = await store.peerByUrl(seed);
        if (existing)
            continue;
        // A seed is the operator's own decision, so it is queried from the start —
        // unlike anything discovered, which only ever becomes a candidate.
        await store.upsertPeer(seed, '', 'seed');
        // Best effort: a seed that is down at boot is still a seed.
        void (0, service_1.announcePeer)(store, config, seed).catch(() => undefined);
    }
}
async function main() {
    const config = (0, config_1.loadConfig)();
    const problems = (0, config_1.checkConfiguration)(config);
    if (problems.length > 0) {
        for (const problem of problems)
            console.error(`config: ${problem}`);
        console.error('see docker/.env.example');
        process.exit(1);
    }
    const store = await openStore(config);
    await adoptSeeds(config, store);
    createApp(config, store).listen(config.port, () => {
        const where = config.store === 'sqlite' ? config.sqlitePath : 'postgres';
        console.log(`trust server listening on :${config.port} (${config.local ? 'local' : 'public'}, ${where})`);
    });
}
if (require.main === module) {
    main().catch((error) => {
        console.error(error);
        process.exit(1);
    });
}
