// ─── Key Store Helpers ─────────────────────────────────────────────────────────
// Single source of truth for blob key names — change here, changes everywhere
export const SESSION_INDEX_KEY = 'index'
export const DEVICE_LIST_INDEX_KEY = 'index'
export const TC_TOKEN_INDEX_KEY = 'index'

// Reads the index blob for a type, consolidating any stray per-file entries first.
//
// Three cases handled in order:
//   1. Legacy blob keys (_index, __index) → moves content to 'index', deletes old key
//   2. Stray per-file entries (type-{id}.json where id !== 'index') → discovered via
//      keys.list(type), merged into index blob, stray files deleted — all in one set()
//   3. Already indexed → returns existing index blob directly
//
// keys.list(type) must be provided by the auth state implementation.
// If not available, case 2 is skipped silently.
export const migrateIndexKey = async (keys, type) => {
    const oldKeys = ['_index', '__index']
    const newKey = 'index'

    // Case 1: migrate legacy blob key names
    for (const oldKey of oldKeys) {
        const oldData = await keys.get(type, [oldKey])
        if (oldData?.[oldKey] != null && typeof oldData[oldKey] === 'object') {
            await keys.set({ [type]: { [newKey]: oldData[oldKey], [oldKey]: null } })
            return oldData[oldKey]
        }
    }

    // Read current index blob
    const indexData = await keys.get(type, [newKey])
    const current = indexData?.[newKey] || {}

    // Case 2: consolidate stray per-file entries using keys.list
    if (typeof keys.list === 'function') {
        const allIds = await keys.list(type)
        const strayIds = allIds.filter(id => id !== newKey && !oldKeys.includes(id))

        if (strayIds.length > 0) {
            const strayData = await keys.get(type, strayIds)
            const merged = { ...current }
            let found = 0
            for (const id of strayIds) {
                if (strayData[id] != null) {
                    merged[id] = strayData[id]
                    found++
                }
            }
            if (found > 0) {
                const deletions = Object.fromEntries(strayIds.map(id => [id, null]))
                await keys.set({ [type]: { [newKey]: merged, ...deletions } })
                return merged
            }
        }
    }

    // Case 3: already indexed
    return current
}