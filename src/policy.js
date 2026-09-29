/** @typedef {import('./types.js').PolicyNode} PolicyNode */
/** @typedef {import('./types.js').PolicyResult} PolicyResult */
/** @typedef {import('./types.js').TelegramApi} TelegramApi */

/**
 * The attributes a policy can inspect. At login these come from the live
 * Telegram update (`ctx.from`); on refresh/introspection from the profile the
 * IdP persisted at the last login.
 * @typedef {object} PolicySubject
 * @property {number} id Telegram user id
 * @property {string} [username]
 * @property {boolean} [is_premium]
 * @property {string} [language_code]
 */

const ACTIVE_STATUSES = ['creator', 'administrator', 'member', 'restricted'];

const CONDITIONS = {
  user_id_in_list: { user_ids: 'array' },
  user_id_not_in_list: { user_ids: 'array' },
  username_matches: { pattern: 'string' },
  group_membership: { chat_id: 'chat' },
  any_group_membership: { chat_ids: 'array' },
  all_group_membership: { chat_ids: 'array' },
  is_premium: { value: 'boolean' },
  language_code_in: { codes: 'array' },
};

/**
 * Throw if `policy` is malformed, so bad policies are rejected when a client
 * is registered instead of silently denying every login.
 * @param {unknown} policy
 * @param {string} [where]
 */
export function validatePolicy(policy, where = 'policy') {
  if (policy === null || policy === undefined) return;
  if (typeof policy !== 'object' || Array.isArray(policy)) throw new Error(`${where} must be an object`);
  const node = /** @type {any} */ (policy);
  if ('operator' in node) {
    if (node.operator === 'and' || node.operator === 'or') {
      if (!Array.isArray(node.conditions) || node.conditions.length === 0) {
        throw new Error(`${where}.conditions must be a non-empty array`);
      }
      node.conditions.forEach((c, i) => validatePolicy(c, `${where}.conditions[${i}]`));
      return;
    }
    if (node.operator === 'not') return validatePolicy(node.condition, `${where}.condition`);
    throw new Error(`${where}.operator must be one of and, or, not`);
  }
  const spec = CONDITIONS[node.type];
  if (!spec) throw new Error(`${where}.type "${node.type}" is not a known condition`);
  for (const [field, kind] of Object.entries(spec)) {
    const v = node[field];
    const ok = kind === 'array' ? Array.isArray(v)
      : kind === 'chat' ? typeof v === 'number' || typeof v === 'string'
      : typeof v === kind;
    if (!ok) throw new Error(`${where}.${field} must be ${kind === 'chat' ? 'a chat id' : `a ${kind}`}`);
  }
  if (node.type === 'username_matches') new RegExp(node.pattern);
}

/**
 * Evaluate a policy tree. Fails closed on anything unexpected.
 * @param {PolicyNode | null | undefined} policy
 * @param {PolicySubject} subject
 * @param {TelegramApi | null} telegram used for group membership lookups
 * @returns {Promise<PolicyResult>}
 */
export async function evaluatePolicy(policy, subject, telegram) {
  if (!policy) return { pass: true };
  try {
    return await evaluateNode(policy, subject, telegram);
  } catch (err) {
    return { pass: false, reason: `Policy error: ${err.message}` };
  }
}

/** @returns {Promise<PolicyResult>} */
async function evaluateNode(node, subject, telegram) {
  if (!node || typeof node !== 'object') return { pass: false, reason: 'Invalid policy node' };
  if ('operator' in node) {
    switch (node.operator) {
      case 'and':
        for (const child of node.conditions) {
          const res = await evaluateNode(child, subject, telegram);
          if (!res.pass) return res;
        }
        return { pass: true };
      case 'or': {
        for (const child of node.conditions) {
          const res = await evaluateNode(child, subject, telegram);
          if (res.pass) return res;
        }
        return { pass: false, reason: 'No condition satisfied' };
      }
      case 'not': {
        const res = await evaluateNode(node.condition, subject, telegram);
        return res.pass ? { pass: false, reason: 'Negated condition matched' } : { pass: true };
      }
      default:
        return { pass: false, reason: `Unknown operator ${node.operator}` };
    }
  }
  return evaluateCondition(node, subject, telegram);
}

/** @returns {Promise<PolicyResult>} */
async function evaluateCondition(cond, subject, telegram) {
  switch (cond.type) {
    case 'user_id_in_list':
      return result(cond.user_ids.includes(subject.id), 'User is not on the allow list');
    case 'user_id_not_in_list':
      return result(!cond.user_ids.includes(subject.id), 'User is on the deny list');
    case 'username_matches':
      return result(!!subject.username && new RegExp(cond.pattern).test(subject.username),
        'Username does not match');
    case 'group_membership':
      return checkGroupMembership(cond.chat_id, cond.role, subject, telegram);
    case 'any_group_membership':
      for (const chatId of cond.chat_ids) {
        if ((await checkGroupMembership(chatId, cond.role, subject, telegram)).pass) return { pass: true };
      }
      return { pass: false, reason: 'User is not a member of any required group' };
    case 'all_group_membership':
      for (const chatId of cond.chat_ids) {
        const res = await checkGroupMembership(chatId, cond.role, subject, telegram);
        if (!res.pass) return res;
      }
      return { pass: true };
    case 'is_premium':
      return result((subject.is_premium === true) === cond.value,
        cond.value ? 'Telegram Premium is required' : 'Telegram Premium users are not allowed');
    case 'language_code_in': {
      // Matches the full IETF tag ("pt-br") or its primary subtag ("pt"), case-insensitively.
      const lang = (subject.language_code || '').toLowerCase();
      const codes = cond.codes.map((c) => String(c).toLowerCase());
      return result(!!lang && (codes.includes(lang) || codes.includes(lang.split('-')[0])),
        'Language is not allowed');
    }
    default:
      return { pass: false, reason: `Unknown condition type ${cond.type}` };
  }
}

function result(pass, reason) {
  return pass ? { pass: true } : { pass: false, reason };
}

/** @returns {Promise<PolicyResult>} */
async function checkGroupMembership(chatId, role, subject, telegram) {
  if (!telegram) return { pass: false, reason: 'Group membership cannot be checked (no Telegram API)' };
  try {
    const { status } = await telegram.getChatMember(chatId, subject.id);
    const pass = !role || role === 'any' ? ACTIVE_STATUSES.includes(status) : status === role;
    return result(pass, `Not a ${role && role !== 'any' ? role : 'member'} of ${chatId}`);
  } catch {
    // Bot not in the chat, chat gone, or API error: fail closed.
    return { pass: false, reason: `Cannot check membership in ${chatId}` };
  }
}
