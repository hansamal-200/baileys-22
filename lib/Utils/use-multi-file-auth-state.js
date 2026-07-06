import { Mutex } from 'async-mutex'
import { mkdir, readFile, rename, stat, unlink, writeFile, readdir } from 'fs/promises'
import { join } from 'path'
import { createHash } from 'crypto'
import { Keyv } from 'keyv'
import { proto } from '../../WAProto/index.js'
import { initAuthCreds } from './auth-utils.js'
import { BufferJSON } from './generics.js'
import { PROTOCOL_ADAPTERS } from '../WABinary/index.js'
const CURRENT_VERSION = 1
const DEFAULT_PREKEY_RETENTION = 150
const DEFAULT_CLEANUP_THRESHOLD = 50
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000

const bootstrapCreds = (raw) => {
    const c = raw ?? initAuthCreds()
    if (!c.__version || c.__version < CURRENT_VERSION) c.__version = CURRENT_VERSION
    return c
}
const patchAppStateKey = (type, v) => type === 'app-state-sync-key' && v ? proto.Message.AppStateSyncKeyData.fromObject(v) : v

const fileLocks = new Map()
const getFileLock = (path) => {
    if (!fileLocks.has(path)) fileLocks.set(path, new Mutex())
    return fileLocks.get(path)
}
const releaseFileLock = (path) => {
    if (fileLocks.has(path) && !fileLocks.get(path).isLocked()) fileLocks.delete(path)
}
const computeChecksum = (data) => createHash('sha256').update(data).digest('hex')

/**
 * Production-grade multi-file auth state for Baileys.
 * Atomic writes, checksum integrity, and smart prekey cleanup.
 * Compatible with standard Baileys auth folder format.
 *
 * @param {string} folder - Directory to store auth files
 * @param {object} [options] - Configuration options
 * @param {number} [options.preKeyRetention=150] - How many recent prekeys to keep
 * @param {number} [options.cleanupThreshold=50] - How many new prekeys trigger a cleanup
 * @param {object} [options.logger] - Optional logger with .info/.warn methods
 */
export const useMultiFileAuthState = async (folder, options = {}) => {
    const {
        preKeyRetention = DEFAULT_PREKEY_RETENTION,
        cleanupThreshold = DEFAULT_CLEANUP_THRESHOLD,
        logger,
    } = options
    const fixFileName = (file) => file?.replace(/\//g, '__')?.replace(/:/g, '-')
    const filePath = (file) => join(folder, fixFileName(file))
    const tmpPath = (file) => filePath(file) + '.tmp'

    const folderInfo = await stat(folder).catch(() => null)
    if (folderInfo) {
        if (!folderInfo.isDirectory()) throw new Error(`Path exists but is not a directory: ${folder}`)
    } else {
        await mkdir(folder, { recursive: true })
    }

    const writeData = async (data, file) => {
        const fp = filePath(file)
        const tp = tmpPath(file)
        const mutex = getFileLock(fp)
        const release = await mutex.acquire()
        try {
            const serialized = JSON.stringify(data, BufferJSON.replacer)
            const checksum = computeChecksum(serialized)
            const payload = JSON.stringify({ data: JSON.parse(serialized), __checksum: checksum })
            await writeFile(tp, payload)
            try {
                await rename(tp, fp)
            } catch {
                await writeFile(fp, payload)
                await unlink(tp).catch(() => { })
            }
        } finally {
            release()
            releaseFileLock(fp)
        }
    }

    const readData = async (file) => {
        const fp = filePath(file)
        const mutex = getFileLock(fp)
        const release = await mutex.acquire()
        try {
            const raw = await readFile(fp, { encoding: 'utf-8' }).catch(() => null)
            if (!raw) return null
            try {
                const parsed = JSON.parse(raw)
                if (parsed.__checksum) {
                    const expected = computeChecksum(JSON.stringify(parsed.data))
                    if (expected !== parsed.__checksum) {
                        logger?.warn({ file }, 'checksum mismatch — reinitializing file')
                        await writeFile(fp, JSON.stringify({ data: parsed.data, __checksum: computeChecksum(JSON.stringify(parsed.data)) })).catch(() => { })
                        return JSON.parse(JSON.stringify(parsed.data), BufferJSON.reviver)
                    }
                    return JSON.parse(JSON.stringify(parsed.data), BufferJSON.reviver)
                }
                const reserialized = JSON.stringify(JSON.parse(raw, BufferJSON.reviver), BufferJSON.replacer)
                const checksum = computeChecksum(reserialized)
                await writeFile(fp, JSON.stringify({ data: JSON.parse(reserialized), __checksum: checksum })).catch(() => { })
                return JSON.parse(raw, BufferJSON.reviver)
            } catch (err) {
                logger?.warn({ file, err: err.message }, 'failed to read auth file — reinitializing')
                await unlink(fp).catch(() => { })
                return null
            }
        } finally { release(); releaseFileLock(fp) }
    }

    const removeData = async (file) => {
        const fp = filePath(file)
        const mutex = getFileLock(fp)
        const release = await mutex.acquire()
        try {
            await unlink(fp).catch(() => { })
        } finally {
            release()
            releaseFileLock(fp)
        }
    }

    let creds = bootstrapCreds(await readData('creds.json'))

    let cleanupRunning = false
    let lastCleanupAt = 0
    let lastCleanedPreKeyId = creds.nextPreKeyId

    const cleanOldPreKeys = async () => {
        const now = Date.now()
        if (cleanupRunning) return
        if (now - lastCleanupAt < CLEANUP_INTERVAL_MS) return
        cleanupRunning = true
        try {
            const minId = creds.nextPreKeyId - preKeyRetention
            if (minId <= 0) return
            const files = await readdir(folder)
            const targets = []
            for (const file of files) {
                const match = file.match(/^pre-key-(\d+)\.json(\.tmp)?$/)
                if (!match) continue
                if (parseInt(match[1], 10) < minId) targets.push(join(folder, file))
            }
            if (!targets.length) return
            await Promise.all(targets.map(f => unlink(f).catch(() => { })))
            lastCleanupAt = Date.now()
            lastCleanedPreKeyId = creds.nextPreKeyId
            logger?.info({ deleted: targets.length, minId }, 'prekey cleanup complete')
        } catch (err) {
            logger?.warn({ err }, 'prekey cleanup failed')
        } finally {
            cleanupRunning = false
        }
    }

    cleanOldPreKeys().catch(() => { })

    const getStats = async () => {
        const files = await readdir(folder).catch(() => [])
        const preKeyFiles = files.filter(f => /^pre-key-\d+\.json$/.test(f))
        return {
            totalFiles: files.length,
            preKeyCount: preKeyFiles.length,
            nextPreKeyId: creds.nextPreKeyId,
            lastCleanupAt: lastCleanupAt ? new Date(lastCleanupAt).toISOString() : null,
        }
    }

    return {
        state: {
            creds,
            keys: {
                get: async (type, ids) => {
                    const data = {}
                    await Promise.all(ids.map(async (id) => {
                        let value = await readData(`${type}-${id}.json`)
                        if (type === 'app-state-sync-key' && value) {
                            value = proto.Message.AppStateSyncKeyData.fromObject(value)
                        }
                        data[id] = value
                    }))
                    return data
                },
                set: async (data) => {
                    const tasks = []
                    for (const category in data) {
                        for (const id in data[category]) {
                            const value = data[category][id]
                            tasks.push(value ? writeData(value, `${category}-${id}.json`) : removeData(`${category}-${id}.json`))
                        }
                    }
                    await Promise.all(tasks)
                },
            },
        },
        saveCreds: async () => {
            if (creds.nextPreKeyId - lastCleanedPreKeyId >= cleanupThreshold) {
                cleanOldPreKeys().catch(() => { })
            }
            return writeData(creds, 'creds.json')
        },
        getStats,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// useKeyvAuthState — Keyv-backed auth state (redis / mongodb / postgres / mysql
// / sqlite / in-memory), resolved from a connection string, Keyv instance, or
// a raw KeyvStoreAdapter. No key registry: prekey cleanup is driven purely by
// creds.nextPreKeyId math. clearSession uses Keyv's own namespace-scoped
// clear() (a native, backend-correct bulk delete on every official adapter).
// Storage format mirrors useMultiFileAuthState exactly: a flat
// { data, __checksum } envelope per value, checksum over the BufferJSON-
// serialized data — Keyv's own {value,expires} transit wrapping happens
// around this string and never touches its contents.
// ═══════════════════════════════════════════════════════════════════════════

const ser = (v) => {
    if (v == null) return null
    const serialized = JSON.stringify(v, BufferJSON.replacer)
    const checksum = computeChecksum(serialized)
    return JSON.stringify({ data: JSON.parse(serialized), __checksum: checksum })
}

// Strips any number of accidental { value: ... } wrapping layers (the shape
// produced by the earlier migration bug, which copied Keyv's own transit
// envelope directly into app data instead of the raw string). Stops as soon
// as what's left no longer looks like a pure single-key wrapper, so it never
// eats into real payload fields that happen to be named "value".
const unwrapNestedValue = (obj) => {
    let cur = obj
    while (cur && typeof cur === 'object' && !Array.isArray(cur) && Object.keys(cur).length === 1 && 'value' in cur) {
        cur = cur.value
    }
    return cur
}

const deser = (raw, logger, onRewrite) => {
    if (raw == null) return null

    // already a parsed object (some stores/paths hand back objects, not strings)
    let parsed
    if (typeof raw === 'string') {
        try { parsed = JSON.parse(raw) } catch (err) {
            logger?.warn?.({ err: err.message }, '[Auth] failed to parse stored value — treating as missing')
            return null
        }
    } else {
        parsed = raw
    }

    // unwrap accidental nested { value: ... } layers before deciding the shape
    parsed = unwrapNestedValue(parsed)
    if (parsed == null) return null

    if (parsed && typeof parsed === 'object' && '__checksum' in parsed) {
        const innerData = unwrapNestedValue(parsed.data)
        const serializedInner = JSON.stringify(innerData)
        const expected = computeChecksum(serializedInner)
        if (expected !== parsed.__checksum) {
            logger?.warn?.('[Auth] checksum mismatch or legacy-wrapped value — reinitializing')
            onRewrite?.(JSON.stringify({ data: innerData, __checksum: expected }))
        }
        return JSON.parse(serializedInner, BufferJSON.reviver)
    }

    // no envelope at all — treat what's left as the raw data itself
    return JSON.parse(JSON.stringify(parsed), BufferJSON.reviver)
}

// Backends that store data in a named collection/table default to "keyv".
// Map our one unified option name to whatever each adapter actually calls it.
const COLLECTION_OPTION_KEY = {
    '@keyv/mongo': 'collection',
    '@keyv/postgres': 'table',
    '@keyv/mysql': 'table',
    '@keyv/sqlite': 'table',
}
// Module-level cache: same connection string + collection name always reuses
// the same underlying adapter instance/connection pool across every session
// and reconnect in the whole process.
const _adapterCache = new Map()
export const clearAdapterCache = () => _adapterCache.clear()

const resolveAdapter = async (connectionString, collectionName) => {
    const cacheKey = collectionName ? `${connectionString}::${collectionName}` : connectionString
    if (_adapterCache.has(cacheKey)) return _adapterCache.get(cacheKey)
    let protocol
    try { protocol = new URL(connectionString).protocol } catch { throw new Error(`[Auth] Invalid connection string: "${connectionString}"`) }
    const pkg = PROTOCOL_ADAPTERS[protocol]
    if (!pkg) throw new Error(`[Auth] Unsupported protocol "${protocol}" — supported: redis, mongodb, postgresql, mysql, sqlite, etcd, memcache. Pass a pre-built KeyvStoreAdapter instance for anything else.`)
    let mod
    try { mod = await import(pkg) } catch (e) {
        if (e.code === 'ERR_MODULE_NOT_FOUND') throw new Error(`[Auth] "${pkg}" is required for this backend — install it: npm i ${pkg}`)
        throw e
    }
    const Adapter = mod.default ?? mod[Object.keys(mod)[0]]
    const optionKey = COLLECTION_OPTION_KEY[pkg]
    // Always pass ONE merged options object (both url and uri set, whichever the
    // adapter reads) rather than (connectionString, options) positionally — Postgres
    // and MySQL's constructors only accept a single argument and silently ignore a
    // second one, so passing options separately would drop the collection name.
    const adapter = (collectionName && optionKey)
        ? new Adapter({ url: connectionString, uri: connectionString, [optionKey]: collectionName })
        : new Adapter(connectionString)
    adapter.setMaxListeners?.(0)
    _adapterCache.set(cacheKey, adapter)
    return adapter
}

const isAdapterLike = (v) => v && typeof v === 'object' && typeof v.get === 'function' && typeof v.set === 'function' && typeof v.delete === 'function' && typeof v.clear === 'function'

const resolveStore = async (backend, collectionName) => {
    if (backend == null) return null
    if (typeof backend === 'string') return resolveAdapter(backend, collectionName)
    if (backend instanceof Keyv) return backend.opts?.store ?? backend.store ?? null
    if (isAdapterLike(backend)) return backend
    throw new Error('[Auth] backend must be a connection string, Keyv instance, or KeyvStoreAdapter')
}

export const useKeyvAuthState = async (sessionId, backend, opts = {}) => {
    const { preKeyRetention = DEFAULT_PREKEY_RETENTION, cleanupThreshold = DEFAULT_CLEANUP_THRESHOLD, logger, collectionName } = opts

    const store = await resolveStore(backend, collectionName)
    const keyv = store ? new Keyv({ store, namespace: sessionId }) : new Keyv({ namespace: sessionId })
    keyv.on('error', (err) => logger?.warn?.({ err: err?.message }, '[Auth] store error'))

    const keyName = (type, id) => `${type}-${id}`

    let creds = bootstrapCreds(deser(await keyv.get('creds'), logger, (fixed) => keyv.set('creds', fixed)))

    let cleanupRunning = false
    let lastCleanupAt = 0
    let lastCleanedPreKeyId = creds.nextPreKeyId

    const cleanOldPreKeys = async () => {
        const now = Date.now()
        if (cleanupRunning || now - lastCleanupAt < CLEANUP_INTERVAL_MS) return
        cleanupRunning = true
        try {
            const minId = creds.nextPreKeyId - preKeyRetention
            if (minId <= 0) return
            const ids = []
            for (let id = Math.max(0, lastCleanedPreKeyId - preKeyRetention); id < minId; id++) ids.push(keyName('pre-key', id))
            if (!ids.length) return
            await Promise.all(ids.map((k) => keyv.delete(k).catch(() => { })))
            lastCleanupAt = Date.now()
            lastCleanedPreKeyId = creds.nextPreKeyId
            logger?.info?.({ deleted: ids.length, minId }, '[Auth] prekey cleanup done')
        } catch (e) {
            logger?.warn?.({ err: e.message }, '[Auth] prekey cleanup failed')
        } finally {
            cleanupRunning = false
        }
    }
    cleanOldPreKeys().catch(() => { })

    const keys = {
        get: async (type, ids) => {
            const data = {}
            if (!ids.length) return data
            const rawKeys = ids.map((id) => keyName(type, id))
            const rawValues = await keyv.getMany(rawKeys)
            const rewrites = []
            ids.forEach((id, i) => {
                const rawKey = rawKeys[i]
                data[id] = patchAppStateKey(type, deser(rawValues[i], logger, (fixed) => rewrites.push(keyv.set(rawKey, fixed))))
            })
            if (rewrites.length) await Promise.all(rewrites).catch(() => { })
            return data
        },
        set: async (data) => {
            const setEntries = []
            const delKeys = []
            for (const type in data) {
                for (const id in data[type]) {
                    const value = data[type][id]
                    const key = keyName(type, id)
                    if (value != null) setEntries.push({ key, value: ser(value) })
                    else delKeys.push(key)
                }
            }
            await Promise.all([
                setEntries.length ? keyv.setMany(setEntries) : null,
                delKeys.length ? keyv.deleteMany(delKeys) : null,
            ])
        },
    }

    const saveCreds = async () => {
        if (creds.nextPreKeyId - lastCleanedPreKeyId >= cleanupThreshold) cleanOldPreKeys().catch(() => { })
        await keyv.set('creds', ser(creds))
    }

    const clearSession = async () => {
        if (typeof store.iterator === 'function') {
            const toDelete = []
            for await (const [key] of store.iterator(sessionId)) {
                toDelete.push(key)
            }
            if (toDelete.length) await store.delete(toDelete)
        } else {
            await keyv.clear()
        }
    }

    const close = async () => { keyv.removeAllListeners?.() }

    return { state: { creds, keys }, saveCreds, clearSession, close }
}

export { Keyv }