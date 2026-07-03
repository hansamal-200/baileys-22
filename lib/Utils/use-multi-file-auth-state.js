import { Mutex } from 'async-mutex'
import { mkdir, readFile, rename, stat, unlink, writeFile, readdir } from 'fs/promises'
import { join } from 'path'
import { createHash } from 'crypto'
import { Keyv } from 'keyv'
import { proto } from '../../WAProto/index.js'
import { initAuthCreds } from './auth-utils.js'
import { BufferJSON } from './generics.js'
import { PROTOCOL_ADAPTERS } from '../WABinary/index.js'
const VERSION = 1
const PRE_KEY_RETENTION = 150
const PRE_KEY_CLEANUP_THRESHOLD = 50
const PRE_KEY_CLEANUP_INTERVAL = 10 * 60 * 1000

const ser = (v) => v == null ? null : JSON.parse(JSON.stringify(v, BufferJSON.replacer))
const deser = (v) => v == null ? null : JSON.parse(JSON.stringify(v), BufferJSON.reviver)
const sha256 = (s) => createHash('sha256').update(s).digest('hex')
const patchAppStateKey = (type, v) => type === 'app-state-sync-key' && v ? proto.Message.AppStateSyncKeyData.fromObject(v) : v
const bootstrapCreds = (raw) => { const c = raw ?? initAuthCreds(); if (!c.__version || c.__version < VERSION) c.__version = VERSION; return c }

// ── Shared prekey cleanup ─────────────────────────────────────────────────────
const makePreKeyCleanup = (keys, getCreds, opts = {}) => {
    const retention = opts.preKeyRetention ?? PRE_KEY_RETENTION
    const threshold = opts.cleanupThreshold ?? PRE_KEY_CLEANUP_THRESHOLD
    const log = opts.logger
    let running = false, lastRun = 0, lastCleaned = getCreds().nextPreKeyId

    const run = async () => {
        if (running || Date.now() - lastRun < PRE_KEY_CLEANUP_INTERVAL) return
        running = true
        try {
            const { nextPreKeyId } = getCreds()
            const minId = nextPreKeyId - retention
            if (minId <= 0) return
            const stale = (await keys.list('pre-key')).filter(id => { const n = +id; return !isNaN(n) && n < minId })
            if (!stale.length) return
            await keys.set({ 'pre-key': Object.fromEntries(stale.map(id => [id, null])) })
            lastRun = Date.now(); lastCleaned = nextPreKeyId
            log?.info?.({ deleted: stale.length, minId }, '[Auth] prekey cleanup done')
        } catch (e) { log?.warn?.({ err: e.message }, '[Auth] prekey cleanup failed') }
        finally { running = false }
    }

    const maybeRun = () => { if (getCreds().nextPreKeyId - lastCleaned >= threshold) run().catch(() => { }) }
    run().catch(() => { })
    return { run, maybeRun }
}

// ── useMultiFileAuthState ─────────────────────────────────────────────────────
// File-based adapter. One JSON file per key, atomic writes (tmp→rename), sha256
// checksum integrity, per-file mutex locking, legacy file upgrade, corrupt file
// recovery, folder auto-create. Exposes keys.list() for migrateIndexKey consolidation.
export const useMultiFileAuthState = async (folder, opts = {}) => {
    const log = opts.logger
    const fix = (f) => f?.replace(/\//g, '__').replace(/:/g, '-')
    const fp = (f) => join(folder, fix(f))
    const tp = (f) => fp(f) + '.tmp'

    const locks = new Map()
    const lock = (p) => { if (!locks.has(p)) locks.set(p, new Mutex()); return locks.get(p) }
    const unlock = (p) => { if (locks.has(p) && !locks.get(p).isLocked()) locks.delete(p) }

    const info = await stat(folder).catch(() => null)
    if (info) { if (!info.isDirectory()) throw new Error(`Not a directory: ${folder}`) }
    else await mkdir(folder, { recursive: true })

    const write = async (data, file) => {
        const p = fp(file), t = tp(file), rel = await lock(p).acquire()
        try {
            const s = JSON.stringify(data, BufferJSON.replacer)
            const payload = JSON.stringify({ data: JSON.parse(s), __checksum: sha256(s) })
            await writeFile(t, payload)
            await rename(t, p).catch(async () => { await writeFile(p, payload); await unlink(t).catch(() => { }) })
        } finally { rel(); unlock(p) }
    }

    const read = async (file) => {
        const p = fp(file), rel = await lock(p).acquire()
        try {
            const raw = await readFile(p, 'utf-8').catch(() => null)
            if (!raw) return null
            try {
                const parsed = JSON.parse(raw)
                if (parsed.__checksum) {
                    const s = JSON.stringify(parsed.data)
                    if (sha256(s) !== parsed.__checksum) { log?.warn?.({ file }, '[Auth] checksum mismatch — rewriting'); await writeFile(p, JSON.stringify({ data: parsed.data, __checksum: sha256(s) })).catch(() => { }) }
                    return JSON.parse(s, BufferJSON.reviver)
                }
                const rs = JSON.stringify(JSON.parse(raw, BufferJSON.reviver), BufferJSON.replacer)
                await writeFile(p, JSON.stringify({ data: JSON.parse(rs), __checksum: sha256(rs) })).catch(() => { })
                return JSON.parse(raw, BufferJSON.reviver)
            } catch (e) { log?.warn?.({ file, err: e.message }, '[Auth] corrupt file — removed'); await unlink(p).catch(() => { }); return null }
        } finally { rel(); unlock(p) }
    }

    const remove = async (file) => { const p = fp(file), rel = await lock(p).acquire(); try { await unlink(p).catch(() => { }) } finally { rel(); unlock(p) } }

    let creds = bootstrapCreds(await read('creds.json'))
    const txMx = new Mutex()

    const keys = {
        list: async (type) => { const files = await readdir(folder).catch(() => []); const pfx = `${fix(type)}-`; return files.filter(f => f.startsWith(pfx) && f.endsWith('.json') && !f.endsWith('.tmp')).map(f => f.slice(pfx.length, -5)) },
        get: async (type, ids) => { const data = {}; await Promise.all(ids.map(async (id) => { data[id] = patchAppStateKey(type, await read(`${type}-${id}.json`)) })); return data },
        set: async (data) => { const t = []; for (const c in data) for (const id in data[c]) { const v = data[c][id]; t.push(v != null ? write(v, `${c}-${id}.json`) : remove(`${c}-${id}.json`)) }; await Promise.all(t) },
        transaction: (fn) => txMx.runExclusive(fn),
    }

    const { maybeRun } = makePreKeyCleanup(keys, () => creds, opts)
    const getStats = async () => { const files = await readdir(folder).catch(() => []); return { totalFiles: files.length, preKeyCount: files.filter(f => /^pre-key-\d+\.json$/.test(f)).length, nextPreKeyId: creds.nextPreKeyId, folder } }

    // Wipes all auth files for this session — call on DisconnectReason.loggedOut.
    // Equivalent to rm -rf folder but surgical — only removes known auth file types.
    const clearSession = async () => {
        const KEY_TYPES = ['session', 'identity-key', 'pre-key', 'sender-key', 'app-state-sync-key', 'app-state-sync-version', 'device-list', 'tctoken', 'lid-mapping']
        const files = await readdir(folder).catch(() => [])
        const targets = files.filter(f => KEY_TYPES.some(t => f.startsWith(`${fix(t)}-`)) && f.endsWith('.json'))
        await Promise.allSettled(targets.map(f => unlink(join(folder, f)).catch(() => { })))
        creds = bootstrapCreds(null)
        await write(creds, 'creds.json')
    }

    return { state: { creds, keys }, saveCreds: async () => { maybeRun(); return write(creds, 'creds.json') }, close: async () => { locks.clear() }, clearSession, getStats }
}

// ── Connection-string auto-resolution ─────────────────────────────────────────
// Dynamically imports the matching @keyv/* adapter from the URI protocol.
// No manual adapter imports needed — just pass a connection string.

const isAdapterLike = (v) => v && typeof v === 'object' && typeof v.get === 'function' && typeof v.set === 'function' && typeof v.delete === 'function'

// ── Module-level adapter cache ────────────────────────────────────────────────
// Keyed by connection string — ensures the same string always returns the same
// adapter instance across all useKeyvAuthState() calls, reconnects, and bots.
// This is critical: without this, every start() call (including reconnects) would
// spawn a brand new DB connection. 300 bots × reconnect = 300+ connections.
// clearAdapterCache() forces fresh connections — useful after a DB failover.
const _adapterCache = new Map()
export const clearAdapterCache = () => _adapterCache.clear()

const resolveByConnectionString = async (str) => {
    if (_adapterCache.has(str)) return _adapterCache.get(str)
    let protocol
    try { protocol = new URL(str).protocol } catch { throw new Error(`[Auth] Invalid connection string: "${str}"`) }
    const pkg = PROTOCOL_ADAPTERS[protocol]
    if (!pkg) throw new Error(`[Auth] Unknown protocol "${protocol}" — supported: ${Object.keys(PROTOCOL_ADAPTERS).join(', ')}. For DynamoDB or other backends, pass a pre-built adapter instance.`)
    let mod
    try { mod = await import(pkg) } catch (e) {
        if (e.code === 'ERR_MODULE_NOT_FOUND') throw new Error(`[Auth] "${pkg}" is required for "${protocol}" — install it: npm i ${pkg}`)
        throw e
    }
    const adapter = new mod.default(str)
    _adapterCache.set(str, adapter)
    return adapter
}

// Normalises a backend value into a raw store for `new Keyv({ store })`.
// null/undefined → in-memory (store omitted). string → auto-resolved and cached.
// Keyv instance → unwrap its store. AdapterLike → use directly.
// Pre-built instances are used as-is — caller is responsible for sharing them.
const normaliseBackend = async (input) => {
    if (input == null) return null
    if (typeof input === 'string') return resolveByConnectionString(input)
    if (input instanceof Keyv) return input.opts?.store ?? input.store ?? null
    if (isAdapterLike(input)) return input
    throw new Error('[Auth] backend must be a connection string, Keyv instance, or KeyvStoreAdapter')
}

// ── makeKeyvAdapter ───────────────────────────────────────────────────────────
// Wraps an async resolveStore(type) into the Baileys keys contract.
// resolveStore is memoised — each type is only resolved/imported once.
const makeKeyvAdapter = (resolveStore, opts = {}) => {
    const log = opts.logger
    const txMx = new Mutex()
    const stripPrefix = (key, type) => { const pfx = `${type}:`; return typeof key === 'string' && key.startsWith(pfx) ? key.slice(pfx.length) : key }

    const keys = {
        list: async (type) => {
            const ids = []
            try { const store = await resolveStore(type); const iter = store.iterator?.() ?? store.generateIterator?.(); if (iter) for await (const [k] of iter) ids.push(stripPrefix(k, type)) }
            catch (e) { log?.warn?.({ type, err: e.message }, '[Auth] list failed') }
            return ids
        },
        get: async (type, ids) => {
            if (!ids.length) return {}
            const store = await resolveStore(type), data = {}
            try { const vals = await store.getMany(ids); for (let i = 0; i < ids.length; i++) data[ids[i]] = patchAppStateKey(type, deser(vals[i])) }
            catch { await Promise.all(ids.map(async (id) => { try { data[id] = patchAppStateKey(type, deser(await store.get(id))) } catch { data[id] = null } })) }
            return data
        },
        set: async (data) => {
            const tasks = []
            for (const type in data) {
                const store = await resolveStore(type)
                for (const id in data[type]) { const v = data[type][id]; tasks.push(v == null ? store.delete(id).catch(e => log?.warn?.({ type, id, err: e.message }, '[Auth] delete failed')) : store.set(id, ser(v)).catch(e => log?.warn?.({ type, id, err: e.message }, '[Auth] set failed'))) }
            }
            await Promise.all(tasks)
        },
        transaction: (fn) => txMx.runExclusive(fn),
    }

    return { keys }
}

// ── useKeyvAuthState ──────────────────────────────────────────────────────────
// Universal adapter for any database backend. Mirrors useMultiFileAuthState —
// sessionId is the first arg (like folder), backend is the second.
// Pass a connection string and the matching @keyv/* adapter is auto-imported.
// Per-type routing supported — route sessions to Postgres, prekeys to SQLite, etc.
// Multiple bots share one backend safely via distinct sessionIds.
//
// Install only the driver(s) you use:
//   npm i @keyv/redis | @keyv/postgres | @keyv/mongo | @keyv/mysql | @keyv/sqlite | @keyv/memcache | @keyv/etcd | @keyv/dynamo
//
// @param {string} sessionId
//   Unique bot session name — scopes all keys (equivalent to folder in useMultiFileAuthState)
// @param {string|Keyv|AdapterLike|{ [type]: string|Keyv|AdapterLike, default? }|null} [backend]
//   Connection string, pre-built Keyv/adapter, or per-type map. Omit for in-memory.
// @param {{ preKeyRetention?, cleanupThreshold?, logger? }} [opts]
//
// @example
// // Connection strings — no adapter imports needed
// const auth = await useKeyvAuthState('bot1', 'redis://localhost:6379')
// const auth = await useKeyvAuthState('bot1', 'postgresql://user:pass@host/db')
// const auth = await useKeyvAuthState('bot1', 'mongodb://localhost/baileys')
// const auth = await useKeyvAuthState('bot1', 'sqlite://auth.db')
// const auth = await useKeyvAuthState('bot1', 'mysql://user:pass@host/db')
//
// // In-memory (testing / ephemeral — data lost on restart)
// const auth = await useKeyvAuthState('test')
//
// // Pre-built instance (for backends without a connection string e.g. DynamoDB)
// import KeyvDynamo from '@keyv/dynamo'
// const auth = await useKeyvAuthState('bot1', new KeyvDynamo({ table: 'baileys', region: 'us-east-1' }))
//
// // Per-type routing — durable keys → Postgres; hot keys → Redis; prekeys → SQLite
// const auth = await useKeyvAuthState('bot1', {
//     default:        'redis://localhost',
//     session:        'postgresql://user:pass@host/db',
//     'sender-key':   'postgresql://user:pass@host/db',
//     'identity-key': 'postgresql://user:pass@host/db',
//     'pre-key':      'sqlite://prekeys.db',
// })
//
// // 300 bots sharing one Postgres — each bot gets its own namespace
// const PG = 'postgresql://user:pass@host/db'
// await Promise.all(sessionIds.map(id => startBot(id, PG)))
export const useKeyvAuthState = async (sessionId, backend, opts = {}) => {
    const isTypeMap = backend != null && typeof backend === 'object' && !(backend instanceof Keyv) && !isAdapterLike(backend) && typeof backend !== 'string'
    const cache = new Map()

    const resolveStore = (type) => {
        if (cache.has(type)) return cache.get(type)
        const promise = (async () => {
            try {
                const raw = isTypeMap ? (backend[type] ?? backend['default']) : backend
                const store = await normaliseBackend(raw)
                // Omit store key entirely when null so Keyv uses its built-in in-memory Map
                return store != null ? new Keyv({ store, namespace: `${sessionId}:${type}` }) : new Keyv({ namespace: `${sessionId}:${type}` })
            } catch (e) {
                cache.delete(type) // evict on failure so next call retries
                throw e
            }
        })()
        cache.set(type, promise)
        return promise
    }

    const { keys } = makeKeyvAdapter(resolveStore, { logger: opts.logger })
    const credsStore = await resolveStore('creds')
    let creds = bootstrapCreds(deser(await credsStore.get('state')))
    const { maybeRun } = makePreKeyCleanup(keys, () => creds, opts)

    const close = async () => { await Promise.allSettled([...cache.values()].map(async (p) => { try { const s = await p; await s.disconnect?.() } catch { } })); cache.clear() }
    const getStats = async () => { const types = [...cache.keys()]; const counts = {}; await Promise.all(types.map(async (t) => { counts[t] = (await keys.list(t)).length })); return { types, counts, sessionId } }

    // Wipes all keys for this session from the backend — call on DisconnectReason.loggedOut.
    // Clears every key type namespace and resets credentials to a fresh state.
    // The module-level adapter cache is preserved so the same connection is reused on next start().
    const KEY_TYPES = ['session', 'identity-key', 'pre-key', 'sender-key', 'app-state-sync-key', 'app-state-sync-version', 'device-list', 'tctoken', 'lid-mapping', 'creds']
    const clearSession = async () => {
        await Promise.allSettled(KEY_TYPES.map(async (type) => {
            try { const store = await resolveStore(type); await store.clear() } catch { }
        }))
        creds = bootstrapCreds(null)
        await credsStore.set('state', ser(creds))
    }

    return { state: { creds, keys }, saveCreds: async () => { maybeRun(); await credsStore.set('state', ser(creds)) }, close, clearSession, getStats }
}

export { Keyv }