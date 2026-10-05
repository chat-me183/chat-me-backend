const PROJECT_ID = 'chat-me-383d6';
const ISSUER = `https://securetoken.google.com/${PROJECT_ID}`;
const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

let jwksCache = null;
let jwksFetchedAt = 0;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra }
  });
}

function cors(request, response) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (() => { try { const o = new URL(origin); return o.origin === 'https://chat-me183.github.io' || (o.protocol === 'http:' && (o.hostname === 'localhost' || o.hostname === '127.0.0.1')); } catch { return false; } })();
  if (!allowed) return response;
  const h = new Headers(response.headers);
  h.set('Access-Control-Allow-Origin', origin);
  h.set('Access-Control-Allow-Credentials', 'false');
  h.set('Vary', 'Origin');
  return new Response(response.body, { status: response.status, headers: h });
}

async function importJwk(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
}

function b64urlToBytes(s) {
  const pad = '='.repeat((4 - s.length % 4) % 4);
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function parseJwt(token) {
  const p = token.split('.');
  if (p.length !== 3) throw new Error('bad_token');
  const dec = s => JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
  return { header: dec(p[0]), payload: dec(p[1]), signingInput: `${p[0]}.${p[1]}`, signature: b64urlToBytes(p[2]) };
}

async function getJwks() {
  if (jwksCache && Date.now() - jwksFetchedAt < 6 * 60 * 60 * 1000) return jwksCache;
  const r = await fetch(JWKS_URL, { cf: { cacheTtl: 21600, cacheEverything: true } });
  if (!r.ok) throw new Error('jwks_unavailable');
  jwksCache = await r.json();
  jwksFetchedAt = Date.now();
  return jwksCache;
}

async function verifyFirebaseToken(token) {
  const { header, payload, signingInput, signature } = parseJwt(token);
  if (header.alg !== 'RS256' || !header.kid) throw new Error('bad_alg');
  const keys = await getJwks();
  const jwk = (keys.keys || []).find(k => k.kid === header.kid);
  if (!jwk) { jwksCache = null; const fresh = await getJwks(); const k = (fresh.keys || []).find(x => x.kid === header.kid); if (!k) throw new Error('unknown_kid'); return verifyWithKey(k); }
  return verifyWithKey(jwk);

  async function verifyWithKey(k) {
    const key = await importJwk(k);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, new TextEncoder().encode(signingInput));
    if (!ok) throw new Error('bad_signature');
    const now = Math.floor(Date.now() / 1000);
    if (payload.iss !== ISSUER || payload.aud !== PROJECT_ID || typeof payload.sub !== 'string' || !payload.sub || !Number.isFinite(Number(payload.exp)) || !Number.isFinite(Number(payload.iat)) || Number(payload.exp) <= now || Number(payload.iat) > now + 60) throw new Error('bad_claims');
    return payload;
  }
}

async function auth(request, env) {
  const m = request.headers.get('Authorization') || '';
  if (!m.startsWith('Bearer ')) throw new Error('auth_required');
  const claims = await verifyFirebaseToken(m.slice(7).trim());
  claims._chatmeRole = await resolveRole(env, claims);
  const id = await identity(env, claims);
  claims._chatmeUsername = id.username;
  claims._chatmeEmail = id.email;
  return claims;
}

function isOwner(claims, env) { return claims._chatmeRole === 'owner' || claims.owner === true || (!!env.OWNER_UID && String(claims.sub || '') === String(env.OWNER_UID)); }
function isAdmin(claims, env) { return isOwner(claims, env) || claims._chatmeRole === 'admin' || claims.admin === true; }
function isModerator(claims, env) { return isAdmin(claims, env) || claims._chatmeRole === 'moderator' || claims.moderator === true; }
function isStaff(claims, env) { return isModerator(claims, env); }

async function assertNotBanned(env, claims) {
  if (isStaff(claims, env)) return;
  const email = String(claims.email || '').toLowerCase();
  if (!email) return;
  const raw = await env.CHATME_KV.get('user:' + email);
  if (!raw) return;
  let u = null; try { u = JSON.parse(raw); } catch {}
  if (!u) return;
  const banned = u.banned === true || String(u.status || '').toLowerCase() === 'banned';
  if (!banned) return;
  const until = u.banUntil ? Date.parse(String(u.banUntil)) : NaN;
  if (Number.isFinite(until) && until <= Date.now()) return;
  throw new Error('account_banned');
}

async function resolveRole(env, claims) {
  if (claims.owner === true || (env.OWNER_UID && String(claims.sub || '') === String(env.OWNER_UID))) return 'owner';
  const stored = await env.CHATME_KV.get('role:' + String(claims.sub || ''));
  return stored === 'admin' || stored === 'moderator' ? stored : (claims.admin === true ? 'admin' : (claims.moderator === true ? 'moderator' : 'user'));
}

function decodeKey(key) {
  const k = String(key || '');
  const m = k.match(/^chat:(.+)__(.+)$/i);
  return { key: k, lower: k.toLowerCase(), userEmail: k.slice(5).toLowerCase(), username: k.slice(6).toLowerCase(), chatUsers: m ? [m[1].toLowerCase(), m[2].toLowerCase()] : null };
}

function rawUserFromValue(value) {
  try { return JSON.parse(value); } catch { return null; }
}

async function identity(env, claims) {
  const email = String(claims.email || '').toLowerCase();
  if (!email) return { email:'', uid:String(claims.user_id || claims.sub || ''), username:'' };
  const raw = await env.CHATME_KV.get('user:' + email);
  let u = null; try { u = raw ? JSON.parse(raw) : null; } catch {}
  return { email, uid:String(claims.user_id || claims.sub || ''), username:String(u?.username || '').toLowerCase() };
}

function sameArrayExceptOwnChange(oldValue, newValue, username, mode) {
  let a=[], b=[];
  try { a = JSON.parse(oldValue || '[]'); b = JSON.parse(newValue || '[]'); } catch { return false; }
  if (!Array.isArray(a) || !Array.isArray(b) || !username) return false;
  const strip = arr => arr.filter(x => String(x).toLowerCase() !== username);
  const sa = strip(a).map(String).sort();
  const sb = strip(b).map(String).sort();
  if (sa.length !== sb.length || sa.some((x,i)=>x.toLowerCase() !== sb[i].toLowerCase())) return false;
  if (mode === 'add') return b.some(x => String(x).toLowerCase() === username) || a.some(x => String(x).toLowerCase() === username);
  return true;
}


function stableValue(x) {
  if (Array.isArray(x)) return x.map(stableValue);
  if (x && typeof x === 'object') return Object.keys(x).sort().reduce((o,k)=>{ o[k]=stableValue(x[k]); return o; },{});
  return x;
}
function sameValue(a,b) { return JSON.stringify(stableValue(a)) === JSON.stringify(stableValue(b)); }
function lowerName(v) { return String(v || '').toLowerCase(); }
function sameArrayIgnoringName(a,b,name) {
  const aa=(Array.isArray(a)?a:[]).filter(x=>lowerName(x)!==lowerName(name)).map(String).sort();
  const bb=(Array.isArray(b)?b:[]).filter(x=>lowerName(x)!==lowerName(name)).map(String).sort();
  return sameValue(aa,bb);
}
function actorOnlyArrayChange(oldArr,nextArr,actor) {
  return Array.isArray(oldArr)&&Array.isArray(nextArr)&&sameArrayIgnoringName(oldArr,nextArr,actor);
}
function actorOnlyReactionChange(oldR,nextR,actor) {
  const a=oldR&&typeof oldR==='object'?oldR:{}; const b=nextR&&typeof nextR==='object'?nextR:{};
  const keys=new Set([...Object.keys(a),...Object.keys(b)]);
  for(const k of keys) {
    const aa=Array.isArray(a[k])?a[k]:[]; const bb=Array.isArray(b[k])?b[k]:[];
    if(!sameArrayIgnoringName(aa,bb,actor)) return false;
  }
  return true;
}
function validateCommentAppend(oldComments,nextComments,actor) {
  if(!Array.isArray(oldComments)||!Array.isArray(nextComments)||nextComments.length!==oldComments.length+1) return false;
  for(let i=0;i<oldComments.length;i++) if(!sameValue(oldComments[i],nextComments[i])) return false;
  const c=nextComments[nextComments.length-1];
  return lowerName(c?.author)===lowerName(actor)&&typeof c?.text==='string'&&c.text.length<=5000;
}
function validatePollVotes(oldPoll,nextPoll,actor) {
  if(!oldPoll||!nextPoll||!sameValue(oldPoll.question,nextPoll.question)||!sameValue(oldPoll.options,nextPoll.options)) return false;
  const a=oldPoll.votes&&typeof oldPoll.votes==='object'?oldPoll.votes:{}; const b=nextPoll.votes&&typeof nextPoll.votes==='object'?nextPoll.votes:{};
  const keys=new Set([...Object.keys(a),...Object.keys(b)]);
  for(const k of keys) {
    const aa=Array.isArray(a[k])?a[k]:[]; const bb=Array.isArray(b[k])?b[k]:[];
    if(!sameArrayIgnoringName(aa,bb,actor)) return false;
  }
  return true;
}
function validatePostMutation(oldValue,newValue,claims,method,isOwnerFlag=false,isAdminFlag=false) {
  const old=rawUserFromValue(oldValue), next=rawUserFromValue(newValue), actor=lowerName(claims._chatmeUsername);
  if(!old||!next||!actor) return false;
  if(method==='delete') return lowerName(old.author)===actor || isOwnerFlag || (isAdminFlag && old._allowAdminDelete===true);
  if(lowerName(old.author)===actor) return next.id===old.id;
  if(isAdminFlag && (lowerName(old.author)===actor || (Array.isArray(old.likes)&&old.likes.some(x=>lowerName(x)===actor)) || (Array.isArray(old.comments)&&old.comments.some(x=>lowerName(x?.author)===actor)) || lowerName(old.sharedFrom?.author)===actor)) return true;
  const immutable=['id','author','authorName','text','type','color','image','time','edited','sharedFrom'];
  for(const k of immutable) if(!sameValue(old[k],next[k])) return false;
  if(!sameValue(old.likes,next.likes)&&!actorOnlyArrayChange(old.likes||[],next.likes||[],actor)) return false;
  if(!sameValue(old.reactions,next.reactions)&&!actorOnlyReactionChange(old.reactions,next.reactions,actor)) return false;
  if(!sameValue(old.comments,next.comments)&&!validateCommentAppend(old.comments||[],next.comments||[],actor)) return false;
  if(!sameValue(old.shareCount,next.shareCount)&&Number(next.shareCount)!==Number(old.shareCount||0)+1) return false;
  if(!sameValue(old.poll,next.poll)&&!validatePollVotes(old.poll,next.poll,actor)) return false;
  const keys=new Set([...Object.keys(old),...Object.keys(next)]);
  for(const k of keys) if(!['id','author','authorName','text','type','color','image','time','edited','sharedFrom','likes','reactions','comments','shareCount','poll'].includes(k)&&!sameValue(old[k],next[k])) return false;
  return true;
}
function validateMessageMutation(oldValue,newValue,actor,isAdmin=false) {
  let old=[],next=[]; try{old=JSON.parse(oldValue||'[]');next=JSON.parse(newValue||'[]')}catch{return false;}
  if(!Array.isArray(old)||!Array.isArray(next)||!actor) return false;
  if(isAdmin && old.some(m=>lowerName(m?.from)===actor)) return true;
  if(next.length===old.length+1){for(let i=0;i<old.length;i++)if(!sameValue(old[i],next[i]))return false;const m=next[next.length-1];return lowerName(m?.from)===actor&&typeof m?.text==='string'&&m.text.length<=5000;}
  if(next.length===old.length){let changed=0;for(let i=0;i<old.length;i++){if(sameValue(old[i],next[i]))continue;changed++;const a=old[i],b=next[i];if(lowerName(a?.from)!==actor)return false;const ar=a?.reactions&&typeof a.reactions==='object'?a.reactions:{};const br=b?.reactions&&typeof b.reactions==='object'?b.reactions:{};const ca={...a};const cb={...b};delete ca.reactions;delete cb.reactions;if(!sameValue(ca,cb)&&!(typeof b.text==='string'&&b.text.length<=5000&&b.edited===true))return false;if(!actorOnlyReactionChange(ar,br,actor))return false;}return changed===1;}
  if(next.length===old.length-1){let j=0,missing=-1;for(let i=0;i<old.length;i++){if(j<next.length&&sameValue(old[i],next[j]))j++;else{if(missing!==-1)return false;missing=i;}}if(missing<0)return false;const m=old[missing];return lowerName(m?.from)===actor||isAdmin;}
  return false;
}
function circleKindAndId(key){const m=String(key||'').match(/^(group|room)chat:(.+)$/i);return m?{kind:m[1].toLowerCase(),id:m[2]}:null;}

async function keyOwnerAllowed(env, claims, key, value, method, oldValue = null) {
  const d = decodeKey(key);
  const id = await identity(env, claims);
  const username = id.username;
  const email = id.email;
  const v = rawUserFromValue(value);

  if (method === 'read') {
    if (d.lower.startsWith('user:')) return true; // response is sanitized for non-staff below
    if (d.lower.startsWith('uname:')) return true;
    if (d.lower.startsWith('friends:')) return true; // friend lists are social/public
    if (d.lower.startsWith('post:') || d.lower.startsWith('challenge:') || d.lower.startsWith('dicechallenge:')) return true;
    if (d.lower.startsWith('gpost:')) {
      const parts=key.split(':'); if(parts.length<3)return false;
      const circle=rawUserFromValue(await env.CHATME_KV.get('group:'+parts[1]));
      return !!circle && (!circle.isPrivate || (Array.isArray(circle.members) && circle.members.some(m=>lowerName(m)===username)));
    }
    if (circleKindAndId(key)) {
      const ci=circleKindAndId(key); if(!ci)return false;
      const circle=rawUserFromValue(await env.CHATME_KV.get(ci.kind+':'+ci.id));
      return !!circle && Array.isArray(circle.members) && circle.members.some(m=>lowerName(m)===username);
    }
    if (d.lower.startsWith('circle:') || d.lower.startsWith('group:') || d.lower.startsWith('room:')) {
      const circle=rawUserFromValue(await env.CHATME_KV.get(key));
      return !!circle && (!circle.isPrivate || (Array.isArray(circle.members) && circle.members.some(m=>lowerName(m)===username)) || (Array.isArray(circle.pendingInvites) && circle.pendingInvites.some(i=>lowerName(i?.username)===username)) || isStaff(claims,env));
    }
    if (d.chatUsers) return !!username && d.chatUsers.includes(username);
    if (d.lower.startsWith('typing:')) return !!username && d.lower.endsWith(':' + username);
    if (d.lower.startsWith('requests:') || d.lower.startsWith('sentreq:') || d.lower.startsWith('notifs:') || d.lower.startsWith('presence:') || d.lower.startsWith('seen:') || d.lower.startsWith('lasttab:') || d.lower.startsWith('dailybonus:') || d.lower.startsWith('bdaycheck:') || d.lower.startsWith('announcedates:') || d.lower.startsWith('gamewins:') || d.lower.startsWith('lastpurchase:') || d.lower.startsWith('privacy:') || d.lower.startsWith('savedposts:') || d.lower.startsWith('storyviews:')) return d.lower.includes(':' + username);
    if (d.lower.startsWith('report:') || d.lower.startsWith('supportticket:') || d.lower.startsWith('audit:') || d.lower.startsWith('purchase:')) return isStaff(claims, env) || d.lower.includes(username);
    return isStaff(claims, env);
  }

  // Privileged writes are deliberately role-aware. Admins/owners may perform
  // administrative account changes, while moderators are restricted to the
  // moderation fields they actually need. No browser-controlled role flag is
  // trusted here.
  if (d.lower.startsWith('user:')) {
    if (isOwner(claims, env)) return true;
    if (isAdmin(claims, env)) {
      const old = rawUserFromValue(oldValue);
      if (old?.isOwner === true || v?.isOwner === true) return false;
      // Roles are authoritative in KV/custom claims, never in editable profile JSON.
      const protectedIdentity = ['isOwner','isSupportAgent','uid','email'];
      if (old && v) for (const k of protectedIdentity) { if (JSON.stringify(old[k]) !== JSON.stringify(v[k])) return false; }
      if (old && v) {
        const targetUid = String(old.uid || v.uid || '').trim();
        const authoritative = targetUid ? await env.CHATME_KV.get('role:' + targetUid) : null;
        const expectedAdmin = authoritative === 'admin';
        const expectedModerator = authoritative === 'moderator';
        if (v.isAdmin !== expectedAdmin || v.isModerator !== expectedModerator) return false;
      }
      return true;
    }
    if (isModerator(claims, env)) {
      const old = rawUserFromValue(oldValue);
      if (!old || !v || old.isOwner === true || old.isAdmin === true || v.isOwner === true || v.isAdmin === true) return false;
      const allowed = ['verified','banned','banReason','banUntil','status','statusUpdatedAt'];
      const keys = new Set([...Object.keys(old), ...Object.keys(v)]);
      for (const k of keys) {
        if (allowed.includes(k)) continue;
        if (JSON.stringify(old[k]) !== JSON.stringify(v[k])) return false;
      }
      return true;
    }
    // A newly registered Firebase user has no KV profile yet. Allow the
    // authenticated user to create exactly their own first user record.
    // This does NOT allow creating or overwriting another user's record.
    if (!oldValue) {
      return d.userEmail === email &&
        v &&
        String(v.uid || '') === id.uid &&
        String(v.email || '').toLowerCase() === email;
    }
    return d.userEmail === email &&
      v &&
      String(v.uid || '') === id.uid &&
      String(v.email || '').toLowerCase() === email;
  }
  if (d.lower.startsWith('audit:')) return isModerator(claims, env);
  if (d.lower.startsWith('purchase:')) {
    const old=rawUserFromValue(oldValue), next=v;
    if (isAdmin(claims,env)) {
      if (!old||!next||!sameValue(old.id,next.id)||!sameValue(old.username,next.username)||!sameValue(old.leos,next.leos)||!sameValue(old.priceNaira,next.priceNaira)||!sameValue(old.reference,next.reference)||!sameValue(old.time,next.time)) return false;
      return old.status==='pending' && (next.status==='approved'||next.status==='rejected');
    }
    if (!oldValue) return !!next && lowerName(next.username)===username && next.status==='pending';
    return false;
  }
  if (d.lower.startsWith('uname:')) return !!username && d.username === username && String(value || '').toLowerCase() === email;
  if (d.lower.startsWith('friends:')) return d.username === username || sameArrayExceptOwnChange(oldValue, value, username, 'change');
  if (d.lower.startsWith('requests:') || d.lower.startsWith('sentreq:')) return d.username === username || sameArrayExceptOwnChange(oldValue, value, username, 'change');
  if (d.lower.startsWith('notifs:')) {
    if (d.username === username) return true;
    const old=rawUserFromValue(oldValue), next=rawUserFromValue(value);
    if (!Array.isArray(old)||!Array.isArray(next)||next.length!==old.length+1) return false;
    for(let i=0;i<old.length;i++) if(!sameValue(old[i],next[i])) return false;
    const n=next[next.length-1];
    const allowedTypes=['message','reaction','comment','like','announcement','welcome','coins_topup','purchase_rejected','friend_request','mention','virtual_gift','purchase_request'];
    return lowerName(n?.from)===username && allowedTypes.includes(String(n?.type||''));
  }
  if (d.lower.startsWith('presence:') || d.lower.startsWith('seen:') || d.lower.startsWith('lasttab:') || d.lower.startsWith('dailybonus:') || d.lower.startsWith('bdaycheck:') || d.lower.startsWith('announcedates:') || d.lower.startsWith('gamewins:') || d.lower.startsWith('lastpurchase:') || d.lower.startsWith('privacy:') || d.lower.startsWith('savedposts:') || d.lower.startsWith('storyviews:')) return d.username === username;
  if (d.chatUsers) {
    if (!d.chatUsers.includes(username) && !isAdmin(claims,env)) return false;
    if (method === 'delete') return true;
    return validateMessageMutation(oldValue,value,username,isAdmin(claims,env));
  }
  if (d.lower.startsWith('typing:')) return d.lower.endsWith(':' + username);
  if (d.lower.startsWith('report:') && isModerator(claims, env)) {
    const old = rawUserFromValue(oldValue);
    if (!old || !v) return false;
    const allowed = ['status','adminReply','repliedBy','repliedAt'];
    const keys = new Set([...Object.keys(old), ...Object.keys(v)]);
    for (const k of keys) { if (allowed.includes(k)) continue; if (JSON.stringify(old[k]) !== JSON.stringify(v[k])) return false; }
    return true;
  }
  if (d.lower.startsWith('supportticket:') && isModerator(claims, env)) {
    const old = rawUserFromValue(oldValue);
    if (!old || !v) return false;
    const allowed = ['status','updatedAt','updatedBy','replies'];
    const keys = new Set([...Object.keys(old), ...Object.keys(v)]);
    for (const k of keys) { if (allowed.includes(k)) continue; if (JSON.stringify(old[k]) !== JSON.stringify(v[k])) return false; }
    return true;
  }
  if (d.lower.startsWith('post:')) return method === 'delete' ? (lowerName(rawUserFromValue(oldValue)?.author) === username || isOwner(claims,env)) : validatePostMutation(oldValue,value,claims,method,isOwner(claims,env),isAdmin(claims,env));
  if (d.lower.startsWith('gpost:')) {
    const parts=key.split(':'); if(parts.length<3)return false;
    const circle=rawUserFromValue(await env.CHATME_KV.get('group:'+parts[1]));
    if(!circle||!Array.isArray(circle.members)||(!circle.members.some(m=>lowerName(m)===username)&&!isAdmin(claims,env)))return false;
    return method === 'delete' ? (lowerName(rawUserFromValue(oldValue)?.author) === username || isAdmin(claims,env)) : validatePostMutation(oldValue,value,claims,method,isOwner(claims,env),isAdmin(claims,env));
  }
  if (circleKindAndId(key)) {
    const ci=circleKindAndId(key); if(!ci)return false;
    const circle=rawUserFromValue(await env.CHATME_KV.get(ci.kind+':'+ci.id));
    if(!circle||!Array.isArray(circle.members)||(!circle.members.some(m=>lowerName(m)===username)&&!isAdmin(claims,env)))return false;
    if(method==='delete') return isAdmin(claims,env) || lowerName(circle.creator)===username;
    return validateMessageMutation(oldValue,value,username,isAdmin(claims,env));
  }
  if (d.lower.startsWith('circle:') || d.lower.startsWith('group:') || d.lower.startsWith('room:')) {
    const old=rawUserFromValue(oldValue)||{}, next=v||{}, actor=username;
    if(method==='delete') return lowerName(old.creator)===actor || isAdmin(claims,env);
    const isMember=o=>Array.isArray(o?.members)&&o.members.some(m=>lowerName(m)===actor);
    const isCreator=o=>lowerName(o?.creator)===actor;
    const isCircleAdmin=o=>Array.isArray(o?.admins)&&o.admins.some(m=>lowerName(m)===actor);
    const privileged=isAdmin(claims,env)||isCreator(old)||isCircleAdmin(old);
    if(!oldValue)return isCreator(next)&&isMember(next)&&lowerName(next.kind)===d.lower.split(':')[0];
    if(!sameValue(old.id,next.id)||!sameValue(old.creator,next.creator)||!sameValue(old.kind,next.kind))return false;
    const invited = Array.isArray(old.pendingInvites)&&old.pendingInvites.some(i=>lowerName(i?.username)===actor);
    const oldMember=isMember(old), nextMember=isMember(next);
    const publicJoin=!old.isPrivate&&!oldMember&&nextMember&&sameArrayIgnoringName(old.members,next.members,actor);
    const membershipKeys=['members','admins','pendingInvites','ownerUid','createdByUid','creatorUid','adminUid'];
    for(const k of membershipKeys) if(!sameValue(old[k],next[k])){
      if(privileged)continue;
      const selfLeave=oldMember&&!nextMember&&sameArrayIgnoringName(old.members,next.members,actor)&&sameArrayIgnoringName(old.admins,next.admins,actor);
      const acceptInvite=invited&&nextMember&&sameArrayIgnoringName(old.members,next.members,actor)&&Array.isArray(next.pendingInvites);
      const declineInvite=invited&&sameValue(old.members,next.members)&&sameArrayIgnoringName(old.pendingInvites,next.pendingInvites,actor);
      if(!(publicJoin||selfLeave||acceptInvite||declineInvite))return false;
    }
    if(!oldMember&&!isCreator(old)&&!isAdmin(claims,env)&&!publicJoin&&!invited)return false;
    const safeFields=['lastActivityAt','pinnedMessage'];
    for(const k of ['name','description','picture','backgroundImage','bannerImage','isPrivate','createdAt',...safeFields]){
      if(sameValue(old[k],next[k]))continue;
      if(privileged)continue;
      if(!safeFields.includes(k))return false;
    }
    return true;
  }
  if (d.lower.startsWith('challenge:') || d.lower.startsWith('dicechallenge:')) {
    const old=rawUserFromValue(oldValue), next=v, actor=username;
    if(!next)return false;
    if(!oldValue){const code=String(next.code||'').toLowerCase();return lowerName(next.creator)===actor&&next.status==='waiting'&&code===d.lower.slice(d.lower.indexOf(':')+1);}
    if(!sameValue(old.code,next.code)||!sameValue(old.creator,next.creator))return false;
    if(old.status==='waiting'&&next.status==='active'){
      if(lowerName(old.creator)===actor||lowerName(next.opponent)!==actor||old.opponent)return false;
      for(const k of ['code','creator','creatorName','bet','createdAt'])if(!sameValue(old[k],next[k]))return false;
      if(d.lower.startsWith('challenge:')){if(typeof next.word!=='string'||typeof next.scrambled!=='string')return false;}
      else if(![next.creatorRoll,next.joinerRoll].every(n=>Number.isInteger(n)&&n>=1&&n<=6))return false;
      return true;
    }
    if(old.status==='waiting'&&next.status==='expired'){const a={...old};const b={...next};delete a.status;delete b.status;return lowerName(old.creator)===actor&&sameValue(a,b);}
    if(old.status==='active'&&(next.status==='finished'||next.status==='tied')){
      if(lowerName(old.creator)!==actor&&lowerName(old.opponent)!==actor)return false;
      const a={...old}; const b={...next}; delete a.status; delete b.status;
      if(next.status==='tied'){ return sameValue(a,b); }
      delete b.winner; delete a.winner; delete b.finishedAt; delete a.finishedAt;
      return lowerName(next.winner)===actor && sameValue(a,b) && Number.isFinite(Number(next.finishedAt));
    }
    return false;
  }
  if (d.lower.startsWith('report:') || d.lower.startsWith('supportticket:')) return username === String(v?.username || v?.reporter || v?.createdBy || '').toLowerCase();
  if (d.lower.startsWith('purchase:')) return username === String(v?.username || '').toLowerCase();
  return isAdmin(claims, env);
}

function publicSanitize(key, value, claims, env) {
  if (isStaff(claims, env)) return value;
  if (!key.toLowerCase().startsWith('user:')) return value;
  const u = rawUserFromValue(value);
  if (!u) return value;
  const safe = { username:u.username, firstName:u.firstName||'', lastName:u.lastName||'', nickname:u.nickname||'', country:u.country||'', createdAt:u.createdAt||null, status:u.status||'', statusUpdatedAt:u.statusUpdatedAt||null, bio:u.bio||'', verified:!!u.verified, profileLocked:!!u.profileLocked, isOwner:false, isAdmin:false, isModerator:false, isSupportAgent:false };
  return JSON.stringify(safe);
}

async function handleStorage(request, env, claims) {
  const url = new URL(request.url);
  const op = url.searchParams.get('op') || 'get';
  const key = url.searchParams.get('key') || '';
  if (!key || key.length > 500) return json({ ok:false, error:'invalid_key' }, 400);

  if (op === 'get') {
    const value = await env.CHATME_KV.get(key);
    if (value == null) return json({ ok:true, value:null });
    if (!await keyOwnerAllowed(env, claims, key, value, 'read')) return json({ ok:false, error:'forbidden' }, 403);
    return json({ ok:true, value:publicSanitize(key, value, claims, env) });
  }
  if (op === 'set') {
    const body = await request.json().catch(() => null);
    const value = body?.value;
    if (typeof value !== 'string' || value.length > 2_000_000) return json({ ok:false, error:'invalid_value' }, 400);
    if (!await keyOwnerAllowed(env, claims, key, value, 'write', await env.CHATME_KV.get(key))) return json({ ok:false, error:'forbidden' }, 403);
    await env.CHATME_KV.put(key, value);
    return json({ ok:true });
  }
  if (op === 'delete') {
    const old = await env.CHATME_KV.get(key);
    if (old != null && !await keyOwnerAllowed(env, claims, key, old, 'delete', old)) return json({ ok:false, error:'forbidden' }, 403);
    await env.CHATME_KV.delete(key);
    return json({ ok:true });
  }
  if (op === 'list') {
    const prefix = url.searchParams.get('prefix') || '';
    if (prefix.length > 300) return json({ ok:false, error:'invalid_prefix' }, 400);
    // Only staff may list arbitrary namespaces. Regular users may list their own username-scoped namespaces.
    const id = await identity(env, claims);
    const pLower = prefix.toLowerCase();
    let listAllowed = isStaff(claims,env);
    let filterChatKeys = false;
    if (!listAllowed && pLower === 'post:') listAllowed = true;
    if (!listAllowed && (pLower === 'presence:' || pLower === 'group:' || pLower === 'room:')) listAllowed = true;
    if (!listAllowed && pLower === 'chat:') { listAllowed = true; filterChatKeys = true; }
    if (!listAllowed && pLower.startsWith('gpost:')) {
      const parts=prefix.split(':');
      if(parts.length>=2){ const circle=rawUserFromValue(await env.CHATME_KV.get('group:'+parts[1])); listAllowed=!!circle&&(!circle.isPrivate||(Array.isArray(circle.members)&&circle.members.some(m=>lowerName(m)===id.username))); }
    }
    if (!listAllowed && ['friends:','requests:','sentreq:','notifs:','presence:','seen:','typing:','savedPosts:','storyViews:'].some(p=>pLower===p+id.username)) listAllowed=true;
    if (!listAllowed) return json({ ok:false, error:'forbidden' }, 403);
    const result = await env.CHATME_KV.list({ prefix, limit: 1000 });
    const keys = filterChatKeys ? result.keys.filter(x => decodeKey(x.name).chatUsers?.includes(id.username)) : result.keys;
    return json({ ok:true, keys: keys.map(x => x.name), cursor: result.list_complete ? null : result.cursor });
  }
  return json({ ok:false, error:'unknown_op' }, 400);
}

async function staffRole(request, env, claims) {
  const current = claims._chatmeRole;
  if (current !== 'owner' && current !== 'admin') return json({ ok:false, error:'forbidden' }, 403);
  const body = await request.json().catch(() => null);
  const uid = String(body?.uid || '').trim();
  const role = String(body?.role || 'user').trim();
  if (!uid || uid.length > 200 || !['user','moderator','admin'].includes(role)) return json({ ok:false, error:'invalid_role_request' }, 400);
  if (uid === String(claims.sub || '') || (env.OWNER_UID && uid === String(env.OWNER_UID))) return json({ ok:false, error:'owner_protected' }, 403);
  if (current === 'admin' && role === 'admin') return json({ ok:false, error:'owner_only' }, 403);
  if (role === 'user') await env.CHATME_KV.delete('role:' + uid);
  else await env.CHATME_KV.put('role:' + uid, role);
  return json({ ok:true, uid, role });
}

async function getRole(request, env, claims) {
  return json({ ok:true, uid:String(claims.sub || ''), role:claims._chatmeRole || 'user' });
}

async function migrateLegacy(request, env, claims) {
  if (!isOwner(claims, env)) return json({ ok:false, error:'owner_only' }, 403);
  const body = await request.json().catch(() => ({}));
  const token = (request.headers.get('Authorization') || '').slice(7).trim();
  if (!token) return json({ ok:false, error:'auth_required' }, 401);
  const database = `(default)`;
  const base = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/${encodeURIComponent(database)}/documents/kv`;
  let pageToken = body.pageToken || '';
  let count = 0;
  let pages = 0;
  do {
    const u = new URL(base); u.searchParams.set('pageSize','300'); if (pageToken) u.searchParams.set('pageToken', pageToken);
    const r = await fetch(u, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) return json({ ok:false, error:'firestore_migration_read_failed', status:r.status }, 502);
    const data = await r.json();
    for (const doc of data.documents || []) {
      const key = doc.name.split('/').pop();
      const value = doc.fields?.value?.stringValue;
      if (key && typeof value === 'string') { await env.CHATME_KV.put(key, value); count++; }
    }
    pageToken = data.nextPageToken || '';
    pages++;
  } while (pageToken && pages < 20);
  return json({ ok:true, migrated:count, nextPageToken:pageToken || null });
}

async function verifyCaptcha(request, env) {
  if (request.method !== 'POST') return json({ success:false, error:'method' }, 405);
  const body = await request.json().catch(() => null);
  const token = body?.token;
  if (!token || !env.RECAPTCHA_SECRET) return json({ success:false }, 400);
  const form = new URLSearchParams({ secret: env.RECAPTCHA_SECRET, response: token });
  const r = await fetch('https://www.google.com/recaptcha/api/siteverify', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:form });
  const data = await r.json().catch(() => ({}));
  return json({ success: data.success === true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') {
      const origin = request.headers.get('Origin') || '';
      const allowed = (() => { try { const o = new URL(origin); return o.origin === 'https://chat-me183.github.io' || (o.protocol === 'http:' && (o.hostname === 'localhost' || o.hostname === '127.0.0.1')); } catch { return false; } })();
      if (!allowed) return new Response('', { status: 403 });
      return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization,Content-Type',
        'Access-Control-Max-Age': '600',
        'Vary': 'Origin'
      }});
    }
    try {
      if (url.pathname === '/' && request.method === 'POST') return cors(request, await verifyCaptcha(request, env));
      if (url.pathname === '/health') return cors(request, json({ ok:true, service:'chat-me-secure' }));
      const claims = await auth(request, env);
      await assertNotBanned(env, claims);
      if (url.pathname === '/role' && request.method === 'GET') return cors(request, await getRole(request, env, claims));
      if (url.pathname === '/staff-role' && request.method === 'POST') return cors(request, await staffRole(request, env, claims));
      if (url.pathname === '/storage') return cors(request, await handleStorage(request, env, claims));
      if (url.pathname === '/migrate-legacy') return cors(request, await migrateLegacy(request, env, claims));
      return cors(request, json({ ok:false, error:'not_found' }, 404));
    } catch (e) {
      const status = e.message === 'auth_required' ? 401 : 403;
      const error = e.message === 'account_banned' ? 'account_banned' : (status === 401 ? 'auth_required' : 'unauthorized');
      return cors(request, json({ ok:false, error }, status));
    }
  }
};
