export async function evaluatePolicy(policy, user, bot) {
  if (!policy) return { pass: true }; // No policy means allow all
  return evaluateNode(policy, user, bot);
}

async function evaluateNode(node, user, bot) {
  if (node.operator) {
    if (node.operator === 'and') {
      for (const child of node.conditions) {
        const res = await evaluateNode(child, user, bot);
        if (!res.pass) return res;
      }
      return { pass: true };
    } else if (node.operator === 'or') {
      for (const child of node.conditions) {
        const res = await evaluateNode(child, user, bot);
        if (res.pass) return res;
      }
      return { pass: false, reason: 'No condition satisfied' };
    } else if (node.operator === 'not') {
      const res = await evaluateNode(node.condition, user, bot);
      return { pass: !res.pass, reason: res.pass ? 'Negated condition true' : undefined };
    }
  } else {
    return evaluateCondition(node, user, bot);
  }
}

async function evaluateCondition(cond, user, bot) {
  switch (cond.type) {
    case 'user_id_in_list':
      return { pass: cond.user_ids.includes(user.id) };

    case 'user_id_not_in_list':
      return { pass: !cond.user_ids.includes(user.id) };

    case 'username_matches':
      return { pass: user.username && new RegExp(cond.pattern).test(user.username) };

    case 'group_membership':
      return checkGroupMembership(cond, user, bot);

    case 'any_group_membership':
      return checkAnyGroupMembership(cond, user, bot);

    case 'all_group_membership':
      return checkAllGroupMembership(cond, user, bot);

    case 'is_premium':
      return { pass: !!user.is_premium === cond.value };

    case 'language_code_in':
      return { pass: user.language_code && cond.codes.includes(user.language_code) };

    default:
      return { pass: false, reason: 'Unknown condition type' };
  }
}

async function checkGroupMembership(cond, user, bot) {
  try {
    const member = await bot.api.getChatMember(cond.chat_id, user.id);
    const status = member.status; // 'creator', 'administrator', 'member', 'restricted', 'left', 'kicked'
    const activeStatuses = ['creator', 'administrator', 'member', 'restricted'];
    if (cond.role) {
      if (cond.role === 'any') {
        return { pass: activeStatuses.includes(status) };
      } else {
        return { pass: status === cond.role };
      }
    } else {
      return { pass: activeStatuses.includes(status) };
    }
  } catch (e) {
    // Bot may not be in the chat, or other API error
    return { pass: false, reason: `Cannot check membership in ${cond.chat_id}` };
  }
}

async function checkAnyGroupMembership(cond, user, bot) {
  for (const chatId of cond.chat_ids) {
    const res = await checkGroupMembership({ chat_id: chatId, role: cond.role || 'any' }, user, bot);
    if (res.pass) return { pass: true };
  }
  return { pass: false, reason: 'User is not a member of any required group' };
}

async function checkAllGroupMembership(cond, user, bot) {
  for (const chatId of cond.chat_ids) {
    const res = await checkGroupMembership({ chat_id: chatId, role: cond.role || 'any' }, user, bot);
    if (!res.pass) return res;
  }
  return { pass: true };
}
