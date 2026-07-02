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
    const identityKeyCache = new LRUCache({ max: 500, ttl: 30 * 60 * 1000, ttlAutopurge: true })

    const storage = signalStorage(auth, lidMapping, logger, lidCache, sessionReadCache, identityKeyCache, withSessionLock)

    // Tracks which PN→LID session migrations have already been done this session
    // so migrateSession is idempotent even if called repeatedly for the same pair.
    const migratedCache = new LRUCache({ ttl: 7 * 24 * 60 * 60 * 1000, ttlAutopurge: true, updateAgeOnGet: true })

    // Wraps every Signal operation in a key-store transaction keyed by the target JID.
    // This ensures read-modify-write cycles (loadSession → decrypt → storeSession) are
    // atomic relative to other operations on the same JID.
    const txn = (fn, key) => parsedKeys.transaction(fn, key)

    return {
        // ── Group messaging ───────────────────────────────────────────────────────

        // Decrypt an incoming group message from authorJid in group.
        // GroupCipher.decrypt(Uint8Array) → Promise<Uint8Array>
        decryptGroupMessage({ group, authorJid, msg }) {
            return txn(
                () => new GroupCipher(storage, group, jidToAddr(authorJid)).decrypt(toU8(msg)),
                group
            )
        },

        // Process an incoming SenderKeyDistributionMessage so we can decrypt future
        // group messages from this sender.
        // SenderKeyDistributionMessage.deserialize(Uint8Array) → SKDM instance
        // GroupSessionBuilder.process(SenderKeyName, SKDM) → Promise<void>
        async processSenderKeyDistributionMessage({ item, authorJid }) {
            if (!item.groupId) throw new Error('Group ID required')
            const senderName = jidToSenderKeyName(item.groupId, authorJid)
            const senderMsg = SenderKeyDistributionMessage.deserialize(
                toU8(item.axolotlSenderKeyDistributionMessage)
            )
            // Do NOT pre-store a blank SenderKeyRecord — new SenderKeyRecord().serialize()
            // returns 0 bytes from the rust bridge and GroupSessionBuilder.process() throws.
            return txn(() => new GroupSessionBuilder(storage).process(senderName, senderMsg), item.groupId)
        },

        // Encrypt a group message and produce the SKDM for first-time recipients.
        // GroupSessionBuilder.create(SenderKeyName) → Promise<SenderKeyDistributionMessage>
        // GroupCipher.encrypt(Uint8Array) → Promise<Uint8Array>
        encryptGroupMessage({ group, meId, data }) {
            return txn(async () => {
                const senderName = jidToSenderKeyName(group, meId)
                const skdm = await new GroupSessionBuilder(storage).create(senderName)
                const ciphertext = await new GroupCipher(storage, group, jidToAddr(meId)).encrypt(toU8(data))
                return { ciphertext, senderKeyDistributionMessage: skdm.serialize() }
            }, group)
        },

        // Returns the serialised SKDM for this sender in group (kept for API completeness).
        getSenderKeyDistributionMessage({ group, meId }) {
            return txn(async () => {
                const senderName = jidToSenderKeyName(group, meId)
                return (await new GroupSessionBuilder(storage).create(senderName)).serialize()
            }, group)
        },

        // Checks whether we have a stored sender key for this group+sender pair.
        // Uses SenderKeyRecord.deserialize() + .isEmpty() for a definitive answer.
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

        // Wipes the sender key for this group+sender so the next send creates a new one.
        deleteSenderKey(group, authorJid) {
            return parsedKeys.set({ 'sender-key': { [jidToSenderKeyName(group, authorJid).toString()]: null } })
        },

        // ── 1:1 messaging ─────────────────────────────────────────────────────────

        // Decrypt an incoming 1:1 message (pkmsg = PreKey, msg = regular Whisper).
        // For pkmsg: extract the sender's identity key from the protobuf before decrypting
        // so we can detect identity changes (re-registrations) before the session is mutated.
        // SessionCipher.decryptPreKeyWhisperMessage(Uint8Array) → Promise<Uint8Array>
        // SessionCipher.decryptWhisperMessage(Uint8Array) → Promise<Uint8Array>
        async decryptMessage({ jid, type, ciphertext }) {
            const addr = jidToAddr(jid)
            const addrStr = addr.toString()
            const cipher = new SessionCipher(storage, addr)

            try {
                return await txn(async () => {
                    if (type === 'pkmsg') {
                        // Extract identity key from PreKeySignalMessage protobuf (field 3)
                        // BEFORE decrypting so we can detect identity changes.
                        const identityKey = extractIdentityFromPkmsg(ciphertext)
                        if (identityKey) {
                            const changed = await storage.saveIdentity(addrStr, identityKey)
                            if (changed) logger?.info?.({ jid }, '[Signal] Identity key changed — session cleared for re-handshake')
                        } else {
                            // This should no longer happen now that we use WAProto decoder.
                            // If it still fires, the ciphertext version byte is wrong or proto is malformed.
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
                // DuplicatedMessage: already processed this message, safely ignore.
                if (e?.message?.includes('DuplicatedMessage')) {
                    logger?.debug?.({ jid }, '[Signal] Duplicate message ignored')
                    return null
                }
                // UntrustedIdentity / InvalidMessage: session is corrupt or identity changed
                // mid-stream. Wipe the session so the next pkmsg creates a fresh one.
                if (e?.message?.includes('UntrustedIdentity') || e?.message?.includes('InvalidMessage')) {
                    logger?.warn?.({ jid, err: e.message }, '[Signal] Session error — wiping session for re-handshake')
                    await storage.wipeSession(addrStr)
                    sessionReadCache.delete(addrStr)
                }
                throw e
            }
        },

        // Encrypt a 1:1 message.
        // SessionCipher.encrypt(Uint8Array) → Promise<{ type: number, body: Uint8Array }>
        // type === 3 means PreKeyWhisperMessage (pkmsg), else regular WhisperMessage (msg).
        encryptMessage({ jid, data }) {
            return txn(async () => {
                const { type: sigType, body } = await new SessionCipher(storage, jidToAddr(jid)).encrypt(toU8(data))
                return { type: sigType === 3 ? 'pkmsg' : 'msg', ciphertext: Buffer.from(body) }
            }, jid)
        },

        // Inject a prekey bundle received from the /encrypt IQ to establish a session.
        // SessionBuilder.processPreKeyBundle(bundle) → Promise<void>
        injectE2ESession({ jid, session }) {
            return txn(() => new SessionBuilder(storage, jidToAddr(jid)).processPreKeyBundle(session), jid)
        },

        // ── Session utilities ──────────────────────────────────────────────────────

        // Returns the Signal protocol address string for a JID (e.g. "23480123:0").
        jidToSignalProtocolAddress: (jid) => jidToAddr(jid).toString(),

        lidMapping,

        // Validates whether a real, open Signal session exists for this JID.
        // Reads the v2 session record and calls SessionRecord.haveOpenSession().
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

        // Wipes sessions for a list of JIDs from the session index.
        // Called on retry exhaustion to force a fresh prekey handshake.
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
        // When WA assigns a LID to a PN user we already have sessions for, we copy
        // those sessions from PN-keyed addresses to LID-keyed addresses so future
        // encryptions use the correct wire JID.

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

        // Bulk-migrates all existing PN sessions to LID on connect, using stored
        // lid-mapping entries. Runs once after CB:success so all subsequent sends
        // use the correct LID wire addresses without per-message migration overhead.
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

        // Pre-warm the LID address cache from known PN→LID mappings on connect
        // so the first decryptMessage per contact skips a DB round-trip.
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
            identityKeyCache.clear()
            lidCache.clear()
            lidMapping.close?.()
        }
    }
}

// ─── Storage Adapter ──────────────────────────────────────────────────────────
// Implements the SignalStorage interface consumed by the whatsapp-rust-bridge WASM.
//
// The bridge calls these methods synchronously from WASM context, so every method
// must return a Promise (bridge awaits them via JS Promise interop).
//
// Session index dual-key pattern (all sessions stored in one 'session.index' blob):
//   v2Key(addr)  →  Uint8Array  (actual binary SessionRecord from SessionRecord.serialize())
//   addr         →  JSON tombstone { version:'v1', _sessions:{} }
//                   Presence of the tombstone = "a session was created here"
//                   Used by assertSessions to check existence without deserializing.
//
// SenderKey storage ('sender-key' namespace):
//   keyId.toString() → Buffer  (raw bytes from SenderKeyRecord.serialize())
//   The bridge calls storeSenderKey with a plain Uint8Array from serialize().
//   We store as Buffer and return toU8() on load.
//
// Never pre-store a blank SenderKeyRecord — new SenderKeyRecord().serialize() returns
// 0 bytes from the rust bridge and GroupSessionBuilder.process() throws on deserialize.

function signalStorage({ creds, keys }, lidMapping, logger, lidCache, sessionReadCache, identityKeyCache, withSessionLock) {

    // Resolves a Signal protocol address string to its LID equivalent.
    // The bridge calls storage methods with the raw address it was constructed with —
    // which may be a PN address (e.g. "23480123_0.0") even after LID assignment.
    // We transparently redirect PN addresses to their LID counterparts.
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

    // Reads the full session index blob through the read cache.
    const getIndex = async () => {
        const cached = sessionReadCache.get('__index__')
        if (cached) return cached
        const batch = await migrateIndexKey(keys, 'session')
        sessionReadCache.set('__index__', batch)
        return batch
    }

    // Writes the full session index blob, serialised through the write lock to
    // prevent concurrent read-modify-write races on the index blob.
    const setIndex = (batch) => withSessionLock(async () => {
        sessionReadCache.set('__index__', batch)
        try {
            await keys.set({ session: { index: batch } })
        } catch (e) {
            // Invalidate cache on write failure so next read hits the store
            sessionReadCache.delete('__index__')
            logger?.error?.(`[Signal] setIndex write failed: ${e.message}`)
            throw e
        }
    })

    // Reads the full identity-key index blob, migrating from per-file format if needed.
    // Result is { [addr]: Uint8Array } stored as identity-key-index.json
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
        // Load a session record for the given address.
        // Returns Uint8Array (binary SessionRecord) or null if no session exists.
        // The rust bridge deserializes this with SessionRecord.deserialize().
        loadSession: async (id) => {
            try {
                const addr = await resolveLID(id)
                // Check per-address cache first (set on store and on previous load)
                const cached = sessionReadCache.get(addr)
                if (cached !== undefined) return cached === null ? null : toU8(cached)
                const batch = await getIndex()
                // Prefer v2 binary record over legacy plain key
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

        // Store a session record for the given address.
        // record is a SessionRecord instance from the rust bridge; call .serialize()
        // to get the raw Uint8Array bytes before storing.
        storeSession: async (id, record) => {
            const addr = await resolveLID(id)
            const serialized = record.serialize()
            const batch = await getIndex()
            // Only write tombstone on first store for this address; thereafter only update v2
            const needsTombstone = !batch[addr] || !isOldJson(batch[addr])
            const updated = {
                ...batch,
                [v2Key(addr)]: serialized,
                ...(needsTombstone ? { [addr]: { version: 'v1', _sessions: {} } } : {}),
            }
            // Update per-address cache immediately so concurrent operations see the new session
            sessionReadCache.set(addr, toU8(serialized))
            await setIndex(updated)
        },

        // Checks whether we trust an inbound identity key for a given address.
        // Returns true if no stored key exists (first contact) or if it matches exactly.
        // The rust bridge calls this before completing decryptPreKeyWhisperMessage.
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

        // Load the stored identity key for an address.
        // Returns Uint8Array or undefined.
        loadIdentityKey: async (id) => {
            const addr = await resolveLID(id)
            const batch = await getIdentityIndex()
            return toU8(batch[addr]) ?? undefined
        },

        // Save an identity key for an address.
        // If the key changed (identity mismatch), wipes the existing session so the
        // next message triggers a fresh PreKey handshake.
        // Returns true if the key was new or changed, false if unchanged.
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
                const updatedIdentity = { ...batch, [addr]: incoming }
                await setIdentityIndex(updatedIdentity)
                lidCache.delete(id)
                return true
            }
            if (!existing) {
                const updatedIdentity = { ...batch, [addr]: incoming }
                await setIdentityIndex(updatedIdentity)
                return true
            }
            return false
        },

        // Exposed for error recovery in decryptMessage — wipes a session on
        // UntrustedIdentity or InvalidMessage errors.
        wipeSession: async (addr) => {
            const batch = await getIndex()
            const updated = { ...batch }
            delete updated[addr]
            delete updated[v2Key(addr)]
            sessionReadCache.delete(addr)
            sessionReadCache.delete('__index__')
            await setIndex(updated)
        },

        // Load a one-time PreKey pair by ID.
        // Returns { pubKey: Uint8Array, privKey: Uint8Array } or null.
        // The rust bridge uses this during processPreKeyBundle / decryptPreKeyWhisperMessage.
        loadPreKey: async (id) => {
            const { [id.toString()]: key } = await keys.get('pre-key', [id.toString()])
            if (!key) return null
            return {
                pubKey: new Uint8Array(Buffer.from(key.public)),
                privKey: new Uint8Array(Buffer.from(key.private))
            }
        },

        // Delete a one-time PreKey after use (Signal protocol requires this).
        removePreKey: (id) => keys.set({ 'pre-key': { [id]: null } }),

        // Load the signed PreKey by ID.
        // Returns { keyId, keyPair: { pubKey, privKey }, signature } or null.
        // Warns if the requested ID doesn't match the current signed prekey (should not happen).
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

        // Load a sender key record for a group+sender pair.
        // keyId is a SenderKeyName.toString() string.
        // Returns Uint8Array (raw bytes for SenderKeyRecord.deserialize()) or null.
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

        // Store a sender key record for a group+sender pair.
        // record is a Uint8Array from SenderKeyRecord.serialize() (rust bridge returns plain Uint8Array).
        // We store as Buffer which is handled correctly by toU8() on load.
        storeSenderKey: async (keyId, record) => {
            await keys.set({ 'sender-key': { [keyId.toString()]: Buffer.from(record) } })
        },

        // Our own Signal registration ID (uint32), sent in prekey messages.
        getOurRegistrationId: () => creds.registrationId,

        // Our own identity key pair used to sign prekeys.
        // generateSignalPubKey prepends the 0x05 Curve25519 type byte expected by Signal.
        getOurIdentity: () => ({
            pubKey: new Uint8Array(generateSignalPubKey(Buffer.from(creds.signedIdentityKey.public))),
            privKey: new Uint8Array(Buffer.from(creds.signedIdentityKey.private))
        })
    }
}

export default makeLibSignalRepository