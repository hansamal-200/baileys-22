import {
    SessionCipher,
    SessionBuilder,
    SessionRecord,
    ProtocolAddress,
    GroupCipher,
    GroupSessionBuilder,
    SenderKeyName,
    SenderKeyDistributionMessage,
} from 'whatsapp-rust-bridge'
import { proto } from '../../WAProto/index.js'
import { LRUCache } from 'lru-cache'
import { generateSignalPubKey, migrateIndexKey } from '../Utils/index.js'
import { isHostedLidUser, isHostedPnUser, isLidUser, isPnUser, jidDecode, transferDevice, WAJIDDomains } from '../WABinary/index.js'
import { LIDMappingStore } from './lid-mapping.js'

// ─── Address Helpers ──────────────────────────────────────────────────────────

const jidToAddr = (jid) => {
    const { user, device, server, domainType } = jidDecode(jid)
    if (!user) throw new Error(`Invalid JID: "${jid}"`)
    if (device === 99 && server !== 'hosted' && server !== 'hosted.lid') throw new Error('Invalid device 99: ' + jid)
    return new ProtocolAddress(
        domainType !== WAJIDDomains.WHATSAPP ? `${user}_${domainType}` : user,
        device || 0
    )
}

const jidToSenderKeyName = (group, user) => new SenderKeyName(group, jidToAddr(user))

// v2Key stores the real binary SessionRecord; plain addr key stores a JSON tombstone
// for backward-compat with old code that checks plain addr existence.
const v2Key = (addr) => `${addr}:v2`

// ─── Buffer Utils ─────────────────────────────────────────────────────────────

const toBuffer = (raw) => {
    if (!raw) return null
    if (raw instanceof Uint8Array) return raw
    if (Buffer.isBuffer(raw)) return raw
    if (raw?.type === 'Buffer' && Array.isArray(raw?.data)) return Buffer.from(raw.data)
    if (Array.isArray(raw)) return Buffer.from(raw)
    if (typeof raw === 'string') return Buffer.from(raw, 'base64')
    if (raw?.data) return Buffer.from(raw.data)
    return null
}

// Converts any binary representation to a proper Uint8Array for the rust bridge.
// The bridge always expects plain Uint8Array — never Buffer or nested objects.
const toU8 = (raw) => {
    const buf = toBuffer(raw)
    if (!buf) return null
    return buf instanceof Uint8Array && buf.constructor === Uint8Array
        ? buf
        : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
}

// Detects legacy JSON session format from old Baileys versions.
const isOldJson = (raw) => {
    if (!raw || raw instanceof Uint8Array || Buffer.isBuffer(raw)) return false
    if (typeof raw === 'object') return 'version' in raw || '_sessions' in raw
    if (typeof raw === 'string') {
        try { const p = JSON.parse(raw); return 'version' in p || '_sessions' in p } catch { return false }
    }
    return false
}

const bufEqual = (a, b) =>
    a && b && a.length === b.length && a.every((byte, i) => byte === b[i])

// ─── Identity Key Extraction ──────────────────────────────────────────────────
// Decodes the PreKeySignalMessage protobuf (field 3 = identityKey, 33 bytes)
// using WAProto's own decoder. The version byte (first byte) is stripped before
// decoding. If extraction fails for any reason, returns undefined — the caller
// falls back to fetching the stored identity key from the key store.
//
// WAProto PreKeySignalMessage field map (confirmed from WAProto/index.js):
//   field 1 (tag 0x08) = registrationId  uint32
//   field 2 (tag 0x12) = baseKey         bytes  (33 bytes)
//   field 3 (tag 0x1A) = identityKey     bytes  (33 bytes)  ← we want this
//   field 4 (tag 0x22) = message         bytes  (variable)
//   field 5 (tag 0x28) = signedPreKeyId  uint32
//   field 6 (tag 0x30) = (unused)

const extractIdentityFromPkmsg = (ciphertext) => {
    try {
        if (!ciphertext || ciphertext.length < 2) return undefined
        // First byte is the Signal version nibble; low 4 bits must be 3 for pkmsg
        if ((ciphertext[0] & 0xf) !== 3) return undefined
        const decoded = proto.PreKeySignalMessage.decode(ciphertext.slice(1))
        const key = decoded.identityKey
        // identityKey must be exactly 33 bytes (1 byte type prefix + 32 bytes curve25519)
        if (key && key.length === 33) return new Uint8Array(key)
        return undefined
    } catch {
        return undefined
    }
}

// ─── Main Factory ─────────────────────────────────────────────────────────────

export function makeLibSignalRepository(auth, logger, pnToLIDFunc) {
    const lidMapping = new LIDMappingStore(auth.keys, logger, pnToLIDFunc)
    const parsedKeys = auth.keys

    // LRU cache for PN→LID address resolution to avoid repeated DB lookups
    const lidCache = new LRUCache({ max: 500, ttl: 5 * 60 * 1000 })

    // Serialises all session index writes — prevents cross-JID races where two
    // concurrent decrypts both read-modify-write the same index blob.
    let sessionIndexWriteLock = Promise.resolve()
    const withSessionLock = (fn) => {
        const next = sessionIndexWriteLock.then(fn).catch(fn)
        sessionIndexWriteLock = next.then(() => { }, () => { })
        return next
    }

    // Per-address session read cache: avoids reading the full index blob on every
    // decrypt. Keyed by resolved LID addr string. Special key '__index__' caches
    // the full index blob for batch reads.
    const sessionReadCache = new LRUCache({ max: 1000, ttl: 5 * 60 * 1000, ttlAutopurge: true })

    const storage = signalStorage(auth, lidMapping, logger, lidCache, sessionReadCache, withSessionLock)

    // Tracks which PN→LID session migrations have already been done this session
    // so migrateSession is idempotent even if called repeatedly for the same pair.
    const migratedCache = new LRUCache({ ttl: 7 * 24 * 60 * 60 * 1000, ttlAutopurge: true, updateAgeOnGet: true })

    // Wraps every Signal operation in a key-store transaction keyed by the target JID.
    // This ensures read-modify-write cycles (loadSession → decrypt → storeSession) are
    // atomic relative to other operations on the same JID.
    const txn = (fn, key) => parsedKeys.transaction(fn, key)

    return {
        // ── Group messaging ───────────────────────────────────────────────────────

        decryptGroupMessage({ group, authorJid, msg }) {
            return txn(
                () => new GroupCipher(storage, group, jidToAddr(authorJid)).decrypt(toU8(msg)),
                group
            )
        },

        async processSenderKeyDistributionMessage({ item, authorJid }) {
            if (!item.groupId) throw new Error('Group ID required')
            const senderName = jidToSenderKeyName(item.groupId, authorJid)
            const senderMsg = SenderKeyDistributionMessage.deserialize(
                toU8(item.axolotlSenderKeyDistributionMessage)
            )
            return txn(() => new GroupSessionBuilder(storage).process(senderName, senderMsg), item.groupId)
        },

        encryptGroupMessage({ group, meId, data }) {
            return txn(async () => {
                const senderName = jidToSenderKeyName(group, meId)
                const skdm = await new GroupSessionBuilder(storage).create(senderName)
                const ciphertext = await new GroupCipher(storage, group, jidToAddr(meId)).encrypt(toU8(data))
                return { ciphertext, senderKeyDistributionMessage: skdm.serialize() }
            }, group)
        },

        getSenderKeyDistributionMessage({ group, meId }) {
            return txn(async () => {
                const senderName = jidToSenderKeyName(group, meId)
                return (await new GroupSessionBuilder(storage).create(senderName)).serialize()
            }, group)
        },

        async hasSenderKey({ group, meId }) {
            const name = jidToSenderKeyName(group, meId).toString()
            const { [name]: raw } = await parsedKeys.get('sender-key', [name])
            const buf = toU8(raw)
            if (!buf) return false
            try {
                return !SenderKeyRecord.deserialize(buf).isEmpty()
            } catch {
                return false
            }
        },

        deleteSenderKey(group, authorJid) {
            return parsedKeys.set({ 'sender-key': { [jidToSenderKeyName(group, authorJid).toString()]: null } })
        },

        // ── 1:1 messaging ─────────────────────────────────────────────────────────

        async decryptMessage({ jid, type, ciphertext }) {
            const addr = jidToAddr(jid)
            const addrStr = addr.toString()
            const cipher = new SessionCipher(storage, addr)

            try {
                return await txn(async () => {
                    if (type === 'pkmsg') {
                        const identityKey = extractIdentityFromPkmsg(ciphertext)
                        if (identityKey) {
                            const changed = await storage.saveIdentity(addrStr, identityKey)
                            if (changed) logger?.info?.({ jid }, '[Signal] Identity key changed — session cleared for re-handshake')
                        } else {
                            logger?.warn?.({ jid }, '[Signal] pkmsg: could not extract identity key from envelope')
                        }
                        return cipher.decryptPreKeyWhisperMessage(toU8(ciphertext))
                    }
                    if (type === 'msg') {
                        return cipher.decryptWhisperMessage(toU8(ciphertext))
                    }
                    throw new Error(`[Signal] Unknown message type: ${type}`)
                }, jid)
            } catch (e) {
                if (e?.message?.includes('DuplicatedMessage')) {
                    logger?.debug?.({ jid }, '[Signal] Duplicate message ignored')
                    return null
                }
                if (e?.message?.includes('UntrustedIdentity') || e?.message?.includes('InvalidMessage')) {
                    logger?.warn?.({ jid, err: e.message }, '[Signal] Session error — wiping session for re-handshake')
                    await storage.wipeSession(addrStr)
                    sessionReadCache.delete(addrStr)
                }
                throw e
            }
        },

        encryptMessage({ jid, data }) {
            return txn(async () => {
                const { type: sigType, body } = await new SessionCipher(storage, jidToAddr(jid)).encrypt(toU8(data))
                return { type: sigType === 3 ? 'pkmsg' : 'msg', ciphertext: Buffer.from(body) }
            }, jid)
        },

        injectE2ESession({ jid, session }) {
            return txn(() => new SessionBuilder(storage, jidToAddr(jid)).processPreKeyBundle(session), jid)
        },

        // ── Session utilities ──────────────────────────────────────────────────────

        jidToSignalProtocolAddress: (jid) => jidToAddr(jid).toString(),

        lidMapping,

        async validateSession(jid) {
            try {
                const addr = jidToAddr(jid).toString()
                const batch = await migrateIndexKey(parsedKeys, 'session')
                const raw = toU8(batch[v2Key(addr)]) ?? toU8(batch[addr])
                if (!raw || isOldJson(raw)) return { exists: false, reason: 'no session' }
                try {
                    return SessionRecord.deserialize(raw).haveOpenSession()
                        ? { exists: true }
                        : { exists: false, reason: 'no open session' }
                } catch {
                    return { exists: false, reason: 'deserialize error' }
                }
            } catch {
                return { exists: false, reason: 'error' }
            }
        },

        async deleteSession(jids) {
            if (!jids?.length) return
            return txn(async () => {
                const batch = await migrateIndexKey(parsedKeys, 'session')
                const updated = { ...batch }
                for (const jid of jids) {
                    const addr = jidToAddr(jid).toString()
                    delete updated[addr]
                    delete updated[v2Key(addr)]
                    sessionReadCache.delete(addr)
                }
                sessionReadCache.delete('__index__')
                await parsedKeys.set({ session: { index: updated } })
            }, `del-${jids.length}`)
        },

        // ── Session migration (PN → LID) ──────────────────────────────────────────

        async migrateSession(fromJid, toJid) {
            if (!fromJid || (!isLidUser(toJid) && !isHostedLidUser(toJid))) return { migrated: 0, skipped: 0, total: 0 }
            if (!isPnUser(fromJid) && !isHostedPnUser(fromJid)) return { migrated: 0, skipped: 0, total: 1 }
            const { user } = jidDecode(fromJid)

            const [deviceListBatch, sessionBatch] = await Promise.all([
                migrateIndexKey(parsedKeys, 'device-list'),
                migrateIndexKey(parsedKeys, 'session'),
            ])

            const userDevices = deviceListBatch[user] ? [...deviceListBatch[user]] : []
            const fromDeviceStr = jidDecode(fromJid).device?.toString() || '0'
            if (!userDevices.includes(fromDeviceStr)) userDevices.push(fromDeviceStr)

            const deviceJids = userDevices
                .filter(d => !migratedCache.has(`${user}.${d}`))
                .map(d => {
                    const num = parseInt(d)
                    return {
                        cacheKey: `${user}.${d}`,
                        jid: num === 99 ? `${user}:99@hosted`
                            : num === 0 ? `${user}@s.whatsapp.net`
                                : `${user}:${num}@s.whatsapp.net`
                    }
                })
                .filter(({ jid }) => {
                    const addr = jidToAddr(jid).toString()
                    return sessionBatch[v2Key(addr)] || sessionBatch[addr]
                })

            if (!deviceJids.length) return { migrated: 0, skipped: 0, total: 0 }

            return txn(async () => {
                const freshBatch = await migrateIndexKey(parsedKeys, 'session')
                const updated = { ...freshBatch }
                let migrated = 0

                for (const { jid, cacheKey } of deviceJids) {
                    const pnAddr = jidToAddr(jid).toString()
                    const lidAddr = jidToAddr(transferDevice(jid, toJid)).toString()
                    const raw = toU8(updated[v2Key(pnAddr)]) ?? toU8(updated[pnAddr])
                    if (!raw || isOldJson(raw)) continue
                    let sess
                    try { sess = SessionRecord.deserialize(raw) } catch { continue }
                    if (!sess.haveOpenSession()) continue
                    updated[v2Key(lidAddr)] = sess.serialize()
                    updated[lidAddr] = { version: 'v1', _sessions: {} }
                    delete updated[v2Key(pnAddr)]
                    delete updated[pnAddr]
                    lidCache.delete(pnAddr)
                    sessionReadCache.delete(pnAddr)
                    migrated++
                    migratedCache.set(cacheKey, true)
                }

                if (migrated > 0) {
                    sessionReadCache.delete('__index__')
                    await parsedKeys.set({ session: { index: updated } })
                }
                return { migrated, skipped: deviceJids.length - migrated, total: deviceJids.length }
            }, `migrate-${jidDecode(toJid)?.user}`)
        },

        async migrateAllPNSessionsToLID() {
            if (!auth.creds?.me?.lid) return 0

            const [sessionBatch, stored] = await (async () => {
                const sb = await migrateIndexKey(parsedKeys, 'session')
                const sessionKeys = Object.keys(sb)
                if (!sessionKeys.length) return [sb, {}]
                const pnAddrs = sessionKeys.filter(addr => {
                    if (addr.endsWith(':v2') || !addr.includes('.')) return false
                    const [, dt] = addr.split('.')[0].split('_')
                    const domainType = parseInt(dt || '0')
                    return domainType === WAJIDDomains.WHATSAPP || domainType === WAJIDDomains.HOSTED
                })
                if (!pnAddrs.length) return [sb, {}]
                const pnUserSet = new Set(pnAddrs.map(addr => addr.split('.')[0].split('_')[0]))
                const s = await parsedKeys.get('lid-mapping', [...pnUserSet])
                return [sb, s]
            })()

            const sessionKeys = Object.keys(sessionBatch)
            if (!sessionKeys.length) return 0

            const pnAddrs = sessionKeys.filter(addr => {
                if (addr.endsWith(':v2') || !addr.includes('.')) return false
                const [, dt] = addr.split('.')[0].split('_')
                const domainType = parseInt(dt || '0')
                return domainType === WAJIDDomains.WHATSAPP || domainType === WAJIDDomains.HOSTED
            })
            if (!pnAddrs.length) return 0

            const pnToLidUserMap = new Map()
            for (const pnUser of new Set(pnAddrs.map(addr => addr.split('.')[0].split('_')[0]))) {
                const lidUser = stored[pnUser]
                if (lidUser && typeof lidUser === 'string') pnToLidUserMap.set(pnUser, lidUser)
            }
            if (!pnToLidUserMap.size) return 0

            return txn(async () => {
                const freshBatch = await migrateIndexKey(parsedKeys, 'session')
                const updated = { ...freshBatch }
                let migrated = 0

                for (const addr of pnAddrs) {
                    const [deviceId, device] = addr.split('.')
                    const [user, dt] = deviceId.split('_')
                    const domainType = parseInt(dt || '0')
                    const lidUser = pnToLidUserMap.get(user)
                    if (!lidUser) continue
                    const lidDomainType = domainType === WAJIDDomains.HOSTED ? WAJIDDomains.HOSTED_LID : WAJIDDomains.LID
                    const lidAddr = `${lidUser}_${lidDomainType}.${device}`
                    if (updated[v2Key(lidAddr)]) continue
                    const raw = toU8(updated[v2Key(addr)]) ?? toU8(updated[addr])
                    if (!raw || isOldJson(raw)) continue
                    let sess
                    try { sess = SessionRecord.deserialize(raw) } catch { continue }
                    if (!sess.haveOpenSession()) continue
                    updated[v2Key(lidAddr)] = sess.serialize()
                    updated[lidAddr] = { version: 'v1', _sessions: {} }
                    delete updated[v2Key(addr)]
                    delete updated[addr]
                    lidCache.delete(addr)
                    sessionReadCache.delete(addr)
                    migrated++
                    migratedCache.set(`${user}.${device}`, true)
                }

                if (migrated > 0) {
                    sessionReadCache.delete('__index__')
                    await parsedKeys.set({ session: { index: updated } })
                    logger?.info?.({ migrated, totalPN: pnAddrs.length, mappingsFound: pnToLidUserMap.size },
                        '[Signal] Batch-migrated PN sessions to LID on connect')
                }
                return migrated
            }, 'migrate-all-pn-to-lid')
        },

        async warmLIDCache(mappings) {
            for (const { pn, lid } of mappings) {
                try {
                    const pnAddr = jidToAddr(pn).toString()
                    const lidAddr = jidToAddr(lid).toString()
                    lidCache.set(pnAddr, lidAddr)
                } catch { }
            }
        },

        close() {
            migratedCache.clear()
            sessionReadCache.clear()
            lidCache.clear()
            lidMapping.close?.()
        }
    }
}

// ─── Storage Adapter ──────────────────────────────────────────────────────────
// Implements the SignalStorage interface consumed by the whatsapp-rust-bridge WASM.
//
// Session index dual-key pattern (all sessions in one 'session-index.json' blob):
//   v2Key(addr)  →  Uint8Array  (binary SessionRecord from SessionRecord.serialize())
//   addr         →  JSON tombstone { version:'v1', _sessions:{} }
//
// Identity key index (all identity keys in one 'identity-key-index.json' blob):
//   addr  →  Uint8Array (33-byte identity key)
//   First read triggers migrateIndexKey which consolidates any stray
//   per-address identity-key-{addr}.json files into the index automatically.
//
// SenderKey storage ('sender-key' namespace, per-keyId files):
//   keyId.toString() → Buffer (raw bytes from SenderKeyRecord.serialize())

function signalStorage({ creds, keys }, lidMapping, logger, lidCache, sessionReadCache, withSessionLock) {

    const resolveLID = async (id) => {
        if (!id.includes('.')) return id
        const cached = lidCache.get(id)
        if (cached) return cached
        const [deviceId, device] = id.split('.')
        const [user, dt] = deviceId.split('_')
        const domainType = parseInt(dt || '0')
        if (domainType === WAJIDDomains.LID || domainType === WAJIDDomains.HOSTED_LID) return id
        const pnJid = `${user}${device !== '0' ? `:${device}` : ''}@${domainType === WAJIDDomains.HOSTED ? 'hosted' : 's.whatsapp.net'}`
        const lid = await lidMapping.getLIDForPN(pnJid)
        const result = lid ? jidToAddr(lid).toString() : id
        lidCache.set(id, result)
        return result
    }

    // ── Session index ────────────────────────────────────────────────────────────

    const getIndex = async () => {
        const cached = sessionReadCache.get('__index__')
        if (cached) return cached
        const batch = await migrateIndexKey(keys, 'session')
        sessionReadCache.set('__index__', batch)
        return batch
    }

    const setIndex = (batch) => withSessionLock(async () => {
        sessionReadCache.set('__index__', batch)
        try {
            await keys.set({ session: { index: batch } })
        } catch (e) {
            sessionReadCache.delete('__index__')
            logger?.error?.(`[Signal] setIndex write failed: ${e.message}`)
            throw e
        }
    })

    // ── Identity key index ───────────────────────────────────────────────────────
    // getIdentityIndex calls migrateIndexKey('identity-key') on first access.
    // migrateIndexKey calls keys.list('identity-key') to discover stray per-address
    // files (identity-key-{addr}.json), merges them into identity-key-index.json,
    // deletes the originals, and returns the merged blob — all in one operation.
    // Subsequent calls hit the LRU cache; no further disk access until TTL expires.

    const identityKeyCache = new LRUCache({ max: 500, ttl: 30 * 60 * 1000, ttlAutopurge: true })

    const getIdentityIndex = async () => {
        const cached = identityKeyCache.get('__index__')
        if (cached) return cached
        const batch = await migrateIndexKey(keys, 'identity-key')
        identityKeyCache.set('__index__', batch)
        return batch
    }

    const setIdentityIndex = async (batch) => {
        identityKeyCache.set('__index__', batch)
        try {
            await keys.set({ 'identity-key': { index: batch } })
        } catch (e) {
            identityKeyCache.delete('__index__')
            logger?.error?.(`[Signal] setIdentityIndex write failed: ${e.message}`)
            throw e
        }
    }

    return {
        // ── Sessions ─────────────────────────────────────────────────────────────

        loadSession: async (id) => {
            try {
                const addr = await resolveLID(id)
                const cached = sessionReadCache.get(addr)
                if (cached !== undefined) return cached === null ? null : toU8(cached)
                const batch = await getIndex()
                const v2 = batch[v2Key(addr)]
                if (v2) {
                    if (isOldJson(v2)) {
                        logger?.debug?.(`[Signal] Corrupt v2 for ${addr} — fresh handshake`)
                        sessionReadCache.set(addr, null)
                        return null
                    }
                    const buf = toU8(v2)
                    if (buf) { sessionReadCache.set(addr, buf); return buf }
                }
                const plain = batch[addr]
                if (!plain || isOldJson(plain)) {
                    if (plain) logger?.debug?.(`[Signal] Old JSON session for ${addr} — fresh handshake`)
                    sessionReadCache.set(addr, null)
                    return null
                }
                const buf = toU8(plain)
                sessionReadCache.set(addr, buf)
                return buf
            } catch (e) {
                logger?.error?.(`[Signal] loadSession error for ${id}: ${e.message}`)
                return null
            }
        },

        storeSession: async (id, record) => {
            const addr = await resolveLID(id)
            const serialized = record.serialize()
            const batch = await getIndex()
            const needsTombstone = !batch[addr] || !isOldJson(batch[addr])
            const updated = {
                ...batch,
                [v2Key(addr)]: serialized,
                ...(needsTombstone ? { [addr]: { version: 'v1', _sessions: {} } } : {}),
            }
            sessionReadCache.set(addr, toU8(serialized))
            await setIndex(updated)
        },

        // ── Identity keys ─────────────────────────────────────────────────────────

        isTrustedIdentity: async (id, identityKey) => {
            try {
                const addr = await resolveLID(id)
                const batch = await getIdentityIndex()
                const existing = toU8(batch[addr])
                if (!existing) return true
                const incoming = identityKey instanceof Uint8Array ? identityKey : toU8(identityKey)
                return !!bufEqual(existing, incoming)
            } catch {
                return true
            }
        },

        loadIdentityKey: async (id) => {
            const addr = await resolveLID(id)
            const batch = await getIdentityIndex()
            return toU8(batch[addr]) ?? undefined
        },

        saveIdentity: async (id, identityKey) => {
            const addr = await resolveLID(id)
            const batch = await getIdentityIndex()
            const existing = toU8(batch[addr])
            const incoming = identityKey instanceof Uint8Array ? identityKey : toU8(identityKey)
            if (existing && !bufEqual(existing, incoming)) {
                // Identity changed — wipe session and update key atomically
                const sessionBatch = await getIndex()
                const updatedSession = { ...sessionBatch }
                delete updatedSession[addr]
                delete updatedSession[v2Key(addr)]
                sessionReadCache.delete(addr)
                sessionReadCache.delete('__index__')
                await setIndex(updatedSession)
                await setIdentityIndex({ ...batch, [addr]: incoming })
                lidCache.delete(id)
                return true
            }
            if (!existing) {
                await setIdentityIndex({ ...batch, [addr]: incoming })
                return true
            }
            return false
        },

        wipeSession: async (addr) => {
            const batch = await getIndex()
            const updated = { ...batch }
            delete updated[addr]
            delete updated[v2Key(addr)]
            sessionReadCache.delete(addr)
            sessionReadCache.delete('__index__')
            await setIndex(updated)
        },

        // ── PreKeys ───────────────────────────────────────────────────────────────

        loadPreKey: async (id) => {
            const { [id.toString()]: key } = await keys.get('pre-key', [id.toString()])
            if (!key) return null
            return {
                pubKey: new Uint8Array(Buffer.from(key.public)),
                privKey: new Uint8Array(Buffer.from(key.private))
            }
        },

        removePreKey: (id) => keys.set({ 'pre-key': { [id]: null } }),

        loadSignedPreKey: (id) => {
            const key = creds.signedPreKey
            if (key.keyId !== id) {
                logger?.warn?.({ requested: id, current: key.keyId }, '[Signal] loadSignedPreKey id mismatch')
                return null
            }
            return {
                keyId: key.keyId,
                keyPair: {
                    pubKey: new Uint8Array(Buffer.from(key.keyPair.public)),
                    privKey: new Uint8Array(Buffer.from(key.keyPair.private))
                },
                signature: new Uint8Array(Buffer.from(key.signature))
            }
        },

        // ── Sender keys ───────────────────────────────────────────────────────────

        loadSenderKey: async (keyId) => {
            try {
                const id = keyId.toString()
                const { [id]: key } = await keys.get('sender-key', [id])
                return toU8(key) ?? null
            } catch (e) {
                logger?.error?.(`[Signal] loadSenderKey error: ${e.message}`)
                return null
            }
        },

        storeSenderKey: async (keyId, record) => {
            await keys.set({ 'sender-key': { [keyId.toString()]: Buffer.from(record) } })
        },

        // ── Own identity ──────────────────────────────────────────────────────────

        getOurRegistrationId: () => creds.registrationId,

        getOurIdentity: () => ({
            pubKey: new Uint8Array(generateSignalPubKey(Buffer.from(creds.signedIdentityKey.public))),
            privKey: new Uint8Array(Buffer.from(creds.signedIdentityKey.private))
        })
    }
}

export default makeLibSignalRepository