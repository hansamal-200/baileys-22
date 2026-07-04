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
const REGISTRY_TYPE_PREFIX = '__registry__'

const ser = (v) => v == null ? null : JSON.parse(JSON.stringify(v, BufferJSON.replacer))
const deser = (v) => v == null ? null : JSON.parse(JSON.stringify(v), BufferJSON.reviver)
const sha256 = (s) => createHash('sha256').update(s).digest('hex')
const patchAppStateKey = (type, v) => type === 'app-state-sync-key' && v ? proto.Message.AppStateSyncKeyData.fromObject(v) : v
const bootstrapCreds = (raw) => { const c = raw ?? initAuthCreds(); if (!c.__version || c.__version < VERSION) c.__version = VERSION; return c }

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
    const clearSession = async () => { const files = await readdir(folder).catch(() => []); const targets = files.filter(f => f.endsWith('.json')); await Promise.allSettled(targets.map(f => unlink(join(folder, f)).catch(() => { }))) }
    return { state: { creds, keys }, saveCreds: async () => { maybeRun(); return write(creds, 'creds.json') }, close: async () => { locks.clear() }, clearSession, getStats }
}

const isAdapterLike = (v) => v && typeof v === 'object' && typeof v.get === 'function' && typeof v.set === 'function' && typeof v.delete === 'function'

// Module-level adapter cache — same connection string always reuses the same instance across sessions/reconnects
const _adapterCache = new Map()
export const clearAdapterCache = () => _adapterCache.clear()

const resolveByConnectionString = async (str) => {
    if (_adapterCache.has(str)) return _adapterCache.get(str)
    let protocol
    try { protocol = new URL(str).protocol } catch { throw new Error(`[Auth] Invalid connection string: "${str}"`) }
    const pkg = PROTOCOL_ADAPTERS[protocol]
    if (!pkg) throw new Error(`[Auth] Unknown protocol "${protocol}" — supported: ${Object.keys(PROTOCOL_ADAPTERS).join(', ')}. For DynamoDB or other backends, pass a pre-built adapter instance.`)
    let mod
    try { mod = await import(pkg) } catch (e) { if (e.code === 'ERR_MODULE_NOT_FOUND') throw new Error(`[Auth] "${pkg}" is required for "${protocol}" — install it: npm i ${pkg}`); throw e }
    const adapter = new mod.default(str)
    _adapterCache.set(str, adapter)
    adapter.setMaxListeners?.(0) // shared singleton — many Keyv wrappers will attach listeners to it
    return adapter
}

const normaliseBackend = async (input) => {
    if (input == null) return null
    if (typeof input === 'string') return resolveByConnectionString(input)
    if (input instanceof Keyv) return input.opts?.store ?? input.store ?? null
    if (isAdapterLike(input)) return input
    throw new Error('[Auth] backend must be a connection string, Keyv instance, or KeyvStoreAdapter')
}

// Self-maintained id registry, one doc per type — avoids Keyv's shared-store iterator/namespace collision and per-type Mutex prevents concurrent write races
const makeKeyRegistry = (resolveStore, sessionId) => {
    const perType = new Map() // type -> { cached: Set|null, mutex: Mutex }
    const registryKeyFor = (type) => `${REGISTRY_TYPE_PREFIX}:${type}`
    const TYPE_LIST_KEY = `${REGISTRY_TYPE_PREFIX}:__types__`
    const typeListMutex = new Mutex()

    const entryFor = (type) => {
        if (!perType.has(type)) perType.set(type, { cached: null, mutex: new Mutex() })
        return perType.get(type)
    }

    const load = async (type) => {
        const entry = entryFor(type)
        if (entry.cached) return entry.cached
        const store = await resolveStore(REGISTRY_TYPE_PREFIX)
        const raw = await store.get(registryKeyFor(type)).catch(() => null)
        entry.cached = new Set(raw ? JSON.parse(raw) : [])
        return entry.cached
    }

    const persist = async (type) => {
        const entry = entryFor(type)
        const store = await resolveStore(REGISTRY_TYPE_PREFIX)
        await store.set(registryKeyFor(type), JSON.stringify([...entry.cached]))
    }

    // Tracks known type names under its own key — never derived from iterator(), so allTypes()/clearSession() coverage doesn't depend on iterator support
    const registerType = async (type) => {
        await typeListMutex.runExclusive(async () => {
            const store = await resolveStore(REGISTRY_TYPE_PREFIX)
            const raw = await store.get(TYPE_LIST_KEY).catch(() => null)
            const known = new Set(raw ? JSON.parse(raw) : [])
            if (known.has(type)) return
            known.add(type)
            await store.set(TYPE_LIST_KEY, JSON.stringify([...known]))
        })
    }

    return {
        addMany: async (entries) => {
            const byType = new Map()
            for (const [type, id] of entries) { if (!byType.has(type)) byType.set(type, []); byType.get(type).push(id) }
            await Promise.all([...byType].map(async ([type, ids]) => {
                await registerType(type)
                await entryFor(type).mutex.runExclusive(async () => {
                    const set = await load(type)
                    for (const id of ids) set.add(id)
                    await persist(type)
                })
            }))
        },
        removeMany: async (entries) => {
            const byType = new Map()
            for (const [type, id] of entries) { if (!byType.has(type)) byType.set(type, []); byType.get(type).push(id) }
            await Promise.all([...byType].map(([type, ids]) => entryFor(type).mutex.runExclusive(async () => {
                const set = await load(type)
                for (const id of ids) set.delete(id)
                await persist(type)
            })))
        },
        list: async (type) => { const set = await entryFor(type).mutex.runExclusive(() => load(type)); return [...set] },
        allTypes: async () => {
            const store = await resolveStore(REGISTRY_TYPE_PREFIX)
            const raw = await store.get(TYPE_LIST_KEY).catch(() => null)
            const known = new Set(raw ? JSON.parse(raw) : [])
            for (const t of perType.keys()) known.add(t) // in-process types not yet flushed
            return [...known]
        },
        clearType: async (type) => { await entryFor(type).mutex.runExclusive(async () => { entryFor(type).cached = new Set(); await persist(type) }) },
    }
}

const makeKeyvAdapter = (resolveStore, registry, opts = {}) => {
    const log = opts.logger
    const txMx = new Mutex()
    const keys = {
        list: async (type) => { try { return await registry.list(type) } catch (e) { log?.warn?.({ type, err: e.message }, '[Auth] list failed'); return [] } },
        get: async (type, ids) => {
            if (!ids.length) return {}
            const store = await resolveStore(type), data = {}
            try { const vals = await store.getMany(ids); for (let i = 0; i < ids.length; i++) data[ids[i]] = patchAppStateKey(type, deser(vals[i])) }
            catch { await Promise.all(ids.map(async (id) => { try { data[id] = patchAppStateKey(type, deser(await store.get(id))) } catch { data[id] = null } })) }
            return data
        },
        set: async (data) => {
            const byType = new Map()
            for (const type in data) { if (!byType.has(type)) byType.set(type, { dels: [], sets: [] }); const b = byType.get(type); for (const id in data[type]) { const v = data[type][id]; if (v == null) b.dels.push(id); else b.sets.push([id, v]) } }

            const deleteTasks = []
            for (const [type, { dels }] of byType) {
                if (!dels.length) continue
                deleteTasks.push((async () => {
                    const store = await resolveStore(type)
                    try { if (typeof store.deleteMany === 'function') await store.deleteMany(dels); else await Promise.all(dels.map(id => store.delete(id))) }
                    catch (e) { log?.warn?.({ type, count: dels.length, err: e.message }, '[Auth] deleteMany failed') }
                })())
            }
            await Promise.all(deleteTasks)

            const setEntries = []
            for (const [type, { sets }] of byType) for (const [id, v] of sets) setEntries.push([type, id, v])
            const CHUNK = 25
            for (let i = 0; i < setEntries.length; i += CHUNK) {
                const batch = setEntries.slice(i, i + CHUNK)
                const stores = new Map()
                await Promise.all(batch.map(async ([type, id, v]) => {
                    if (!stores.has(type)) stores.set(type, resolveStore(type))
                    const store = await stores.get(type)
                    return store.set(id, ser(v)).catch(e => log?.warn?.({ type, id, err: e.message }, '[Auth] set failed'))
                }))
                if (i + CHUNK < setEntries.length) await new Promise(r => setImmediate(r))
            }

            const registryDels = [], registrySets = []
            for (const [type, { dels, sets }] of byType) { for (const id of dels) registryDels.push([type, id]); for (const [id] of sets) registrySets.push([type, id]) }
            if (registryDels.length) await registry.removeMany(registryDels).catch(e => log?.warn?.({ err: e.message }, '[Auth] registry removeMany failed'))
            if (registrySets.length) await registry.addMany(registrySets).catch(e => log?.warn?.({ err: e.message }, '[Auth] registry addMany failed'))
        },
        transaction: (fn) => txMx.runExclusive(fn),
    }
    return { keys }
}

export const useKeyvAuthState = async (sessionId, backend, opts = {}) => {
    const isTypeMap = backend != null && typeof backend === 'object' && !(backend instanceof Keyv) && !isAdapterLike(backend) && typeof backend !== 'string'
    const cache = new Map()
    const resolveStore = (type) => {
        if (cache.has(type)) return cache.get(type)
        const promise = (async () => { try { const raw = isTypeMap ? (backend[type] ?? backend['default']) : backend; const store = await normaliseBackend(raw); return store != null ? new Keyv({ store, namespace: `${sessionId}:${type}` }) : new Keyv({ namespace: `${sessionId}:${type}` }) } catch (e) { cache.delete(type); throw e } })()
        cache.set(type, promise)
        return promise
    }
    const registry = makeKeyRegistry(resolveStore, sessionId)
    const { keys } = makeKeyvAdapter(resolveStore, registry, { logger: opts.logger })
    const credsStore = await resolveStore('creds')
    let creds = bootstrapCreds(deser(await credsStore.get('state')))
    const { maybeRun } = makePreKeyCleanup(keys, () => creds, opts)
    // Only drops local references for GC — never calls .disconnect(), since the underlying store is shared via _adapterCache across other sessions
    const close = async () => { cache.clear() }
    const getStats = async () => { const types = [...cache.keys()]; const counts = {}; await Promise.all(types.map(async (t) => { counts[t] = (await keys.list(t)).length })); return { types, counts, sessionId } }
    const clearSession = async () => {
        const types = await registry.allTypes()
        await Promise.all(types.map(async (type) => {
            const ids = await registry.list(type)
            if (ids.length) {
                const store = await resolveStore(type)
                try { if (typeof store.deleteMany === 'function') await store.deleteMany(ids); else await Promise.all(ids.map(id => store.delete(id))) } catch { }
            }
            await registry.clearType(type).catch(() => { })
        }))
        await credsStore.delete('state').catch(() => { })
    }
    return { state: { creds, keys }, saveCreds: async () => { maybeRun(); await credsStore.set('state', ser(creds)) }, close, clearSession, getStats }
}

export { Keyv }