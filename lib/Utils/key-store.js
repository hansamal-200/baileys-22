// ─── Key Store Helpers ─────────────────────────────────────────────────────────
// Single source of truth for blob key names — change here, changes everywhere
export const SESSION_INDEX_KEY = 'index'
export const DEVICE_LIST_INDEX_KEY = 'index'
export const TC_TOKEN_INDEX_KEY = 'index'

// Migrates old _index blob to new index key in-place, returns the batch data
export const migrateIndexKey = async (keys, type) => {
    const oldKeys = ['_index', '__index']
    const newKey = 'index'

    for (const oldKey of oldKeys) {
        const oldData = await keys.get(type, [oldKey])
        if (oldData?.[oldKey] !== null && oldData?.[oldKey] !== undefined && typeof oldData[oldKey] === 'object') {
            await keys.set({ [type]: { [newKey]: oldData[oldKey], [oldKey]: null } })
            return oldData[oldKey]
        }
    }

    const newData = await keys.get(type, [newKey])
    return newData?.[newKey] || {}
}