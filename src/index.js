/**
 * Buist Knights — API worker.
 *
 * Accounts are issued, not requested. There is no public sign-up: an admin
 * creates every coach and player, sets their username and password, and puts
 * them on a team. That is the only way onto the system.
 *
 *   meta         — schema version, so a shape change can rebuild cleanly
 *   users        — one row per person; password only ever a PBKDF2 hash
 *   sessions     — opaque tokens handed out at login, kept in an HttpOnly cookie
 *   teams        — a team; membership is assigned by an admin, never claimed
 *   memberships  — who is on which team, and whether they coach it
 *   team_docs    — the team's content (roster, schedule, plays…) as JSON
 *
 * The doc is one JSON blob on purpose: the front end already worked on exactly
 * that object, so moving it to the server never required reshaping the app.
 */

const SCHEMA_VERSION = 6;
const MAX_MESSAGE = 2000;
const MAX_LOGO = 400_000;      // a data URL this big is already a 256px PNG
const SESSION_DAYS = 60;
const PBKDF2_ITER = 100_000;
const MAX_DOC_BYTES = 2_000_000;
const LOCK_AFTER = 6;              // failed logins before a cooling-off period
const LOCK_MINUTES = 15;

/* ---------------------------------------------------------------- helpers */

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });

const bad = (message, status = 400) => json({ error: message }, status);
const now = () => Date.now();
const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const randomHex = (bytes) => hex(crypto.getRandomValues(new Uint8Array(bytes)));
const uid = () => randomHex(12);

async function hashPassword(password, saltHex) {
  const salt = saltHex ? Uint8Array.from(saltHex.match(/../g).map(h => parseInt(h, 16)))
                       : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, key, 256);
  return { hash: hex(bits), salt: hex(salt) };
}

// compare without leaking where the mismatch is
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const cleanUsername = (u) => String(u || '').trim().toLowerCase();
const usernameProblem = (u) => {
  if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(u))
    return 'Usernames are 3–32 characters: letters, numbers, dot, dash or underscore.';
  return null;
};
function passwordProblem(pw) {
  if (typeof pw !== 'string' || pw.length < 8) return 'Password must be at least 8 characters.';
  if (pw.length > 200) return 'Password is too long.';
  return null;
}

const cookieHeader = (token, maxAgeSeconds) =>
  [`sid=${token}`, 'Path=/', 'HttpOnly', 'Secure', 'SameSite=Lax', `Max-Age=${maxAgeSeconds}`].join('; ');

function readCookie(request, name) {
  const raw = request.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

/* ------------------------------------------------------------------ schema */

let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)').run();
  const row = await env.DB.prepare("SELECT v FROM meta WHERE k = 'schema_version'").first();
  const version = row ? parseInt(row.v, 10) : 0;

  const programTable = `CREATE TABLE IF NOT EXISTS programs (
       id TEXT PRIMARY KEY, name TEXT NOT NULL, sport TEXT NOT NULL,
       logo TEXT, created_at INTEGER NOT NULL)`;

  const messagingTables = [
    `CREATE TABLE IF NOT EXISTS messages (
       id TEXT PRIMARY KEY, team_id TEXT NOT NULL, thread TEXT NOT NULL,
       sender_id TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL)`,
    `CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(team_id, thread, created_at)`,
    `CREATE TABLE IF NOT EXISTS reads (
       user_id TEXT NOT NULL, team_id TEXT NOT NULL, thread TEXT NOT NULL,
       last_read INTEGER NOT NULL, PRIMARY KEY (user_id, team_id, thread))`,
  ];

  if (version > 0 && version < SCHEMA_VERSION) {
    // upgrades only add things, so live accounts and teams are left alone
    if (version < 4) {
      try { await env.DB.prepare("ALTER TABLE teams ADD COLUMN sport TEXT NOT NULL DEFAULT 'basketball'").run(); }
      catch (e) { /* already there */ }
    }
    for (const q of messagingTables) await env.DB.prepare(q).run();
    if (version < 6) {
      await env.DB.prepare(programTable).run();
      try { await env.DB.prepare('ALTER TABLE teams ADD COLUMN program_id TEXT').run(); }
      catch (e) { /* already there */ }
      // file any existing teams under one program per sport, so nothing is orphaned
      const sports = (await env.DB.prepare(
        'SELECT DISTINCT sport FROM teams WHERE program_id IS NULL').all()).results || [];
      for (const row of sports) {
        const sport = row.sport || 'basketball';
        const pid = uid();
        await env.DB.prepare('INSERT INTO programs (id, name, sport, logo, created_at) VALUES (?,?,?,NULL,?)')
          .bind(pid, 'Buist ' + (sport === 'lacrosse' ? 'Lacrosse' : 'Basketball'), sport, now()).run();
        await env.DB.prepare('UPDATE teams SET program_id = ? WHERE program_id IS NULL AND sport = ?')
          .bind(pid, sport).run();
      }
    }
    await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('schema_version', ?)")
      .bind(String(SCHEMA_VERSION)).run();
    schemaReady = true;
    return;
  }

  if (version < SCHEMA_VERSION) {
    // first run only: build the tables from scratch
    for (const t of ['sessions', 'memberships', 'team_docs', 'teams', 'users']) {
      await env.DB.prepare(`DROP TABLE IF EXISTS ${t}`).run();
    }
    const stmts = [
      `CREATE TABLE users (
         id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
         pw_hash TEXT NOT NULL, pw_salt TEXT NOT NULL,
         is_admin INTEGER NOT NULL DEFAULT 0, must_change INTEGER NOT NULL DEFAULT 0,
         failed INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0,
         created_at INTEGER NOT NULL)`,
      `CREATE TABLE sessions (
         token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
         created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)`,
      `CREATE INDEX idx_sessions_user ON sessions(user_id)`,
      `CREATE TABLE teams (
         id TEXT PRIMARY KEY, name TEXT NOT NULL, grade TEXT NOT NULL,
         sport TEXT NOT NULL DEFAULT 'basketball', program_id TEXT,
         created_by TEXT NOT NULL, created_at INTEGER NOT NULL)`,
      `CREATE TABLE memberships (
         team_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL,
         created_at INTEGER NOT NULL, PRIMARY KEY (team_id, user_id))`,
      `CREATE INDEX idx_memberships_user ON memberships(user_id)`,
      `CREATE TABLE team_docs (
         team_id TEXT PRIMARY KEY, doc TEXT NOT NULL, rev INTEGER NOT NULL DEFAULT 1,
         updated_at INTEGER NOT NULL, updated_by TEXT)`,
      programTable,
      ...messagingTables,
    ];
    for (const s of stmts) await env.DB.prepare(s).run();
    await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('schema_version', ?)")
      .bind(String(SCHEMA_VERSION)).run();
  }
  schemaReady = true;
}

/* -------------------------------------------------------------------- auth */

async function newSession(env, userId) {
  const token = randomHex(32);
  const created = now();
  await env.DB.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)')
    .bind(token, userId, created, created + SESSION_DAYS * 86400_000).run();
  return { token, maxAge: SESSION_DAYS * 86400 };
}

async function currentUser(request, env) {
  const token = readCookie(request, 'sid');
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.username, u.name, u.is_admin, u.must_change, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`).bind(token).first();
  if (!row) return null;
  if (row.expires_at < now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  return { id: row.id, username: row.username, name: row.name,
           isAdmin: !!row.is_admin, mustChange: !!row.must_change, token };
}

const publicUser = (u) => ({ id: u.id, username: u.username, name: u.name, isAdmin: u.isAdmin, mustChange: u.mustChange });

async function roleOn(env, teamId, userId) {
  const row = await env.DB.prepare('SELECT role FROM memberships WHERE team_id = ? AND user_id = ?')
    .bind(teamId, userId).first();
  return row ? row.role : null;
}

async function teamsFor(env, userId, isAdmin) {
  // An admin can always reach every team, whether or not they're on it —
  // otherwise setting up a team would lock them out of the app.
  if (isAdmin) {
    const { results } = await env.DB.prepare(
      `SELECT t.id, t.name, t.grade, COALESCE(p.sport, t.sport) AS sport,
              t.program_id AS programId, p.name AS programName, COALESCE(m.role, 'admin') AS role
         FROM teams t
         LEFT JOIN programs p ON p.id = t.program_id
         LEFT JOIN memberships m ON m.team_id = t.id AND m.user_id = ?
        ORDER BY p.name, t.grade, t.name`).bind(userId).all();
    return results || [];
  }
  const { results } = await env.DB.prepare(
    `SELECT t.id, t.name, t.grade, COALESCE(p.sport, t.sport) AS sport,
            t.program_id AS programId, p.name AS programName, m.role
       FROM memberships m JOIN teams t ON t.id = m.team_id
       LEFT JOIN programs p ON p.id = t.program_id
      WHERE m.user_id = ? ORDER BY p.name, t.grade, t.name`).bind(userId).all();
  return results || [];
}

async function userCount(env) {
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
  return r ? r.n : 0;
}

/* ------------------------------------------------------------------ routes */

async function handleApi(request, env, url) {
  const path = url.pathname.replace(/^\/api/, '') || '/';
  const method = request.method.toUpperCase();
  let body = {};
  if (method !== 'GET' && method !== 'DELETE') {
    try { body = await request.json(); } catch (e) { body = {}; }
  }

  /* ---- public ---- */

  if (path === '/status' && method === 'GET') {
    return json({ needsSetup: (await userCount(env)) === 0 });
  }

  // One-time bootstrap. Works only while there are no accounts at all, so it
  // cannot be used to add an admin later.
  if (path === '/setup' && method === 'POST') {
    if ((await userCount(env)) > 0) return bad('Setup has already been completed.', 403);
    const username = cleanUsername(body.username);
    const name = String(body.name || '').trim();
    const uErr = usernameProblem(username); if (uErr) return bad(uErr);
    if (name.length < 2) return bad('Enter your name.');
    const pErr = passwordProblem(body.password); if (pErr) return bad(pErr);

    const { hash, salt } = await hashPassword(body.password);
    const id = uid();
    await env.DB.prepare(
      `INSERT INTO users (id, username, name, pw_hash, pw_salt, is_admin, must_change, created_at)
       VALUES (?,?,?,?,?,1,0,?)`).bind(id, username, name, hash, salt, now()).run();
    const { token, maxAge } = await newSession(env, id);
    return json({ user: { id, username, name, isAdmin: true, mustChange: false }, teams: [] },
      200, { 'set-cookie': cookieHeader(token, maxAge) });
  }

  if (path === '/login' && method === 'POST') {
    const username = cleanUsername(body.username);
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    const generic = 'Username or password is incorrect.';
    if (!user) return bad(generic, 401);
    if (user.locked_until > now()) {
      const mins = Math.ceil((user.locked_until - now()) / 60000);
      return bad(`Too many attempts. Try again in ${mins} minute${mins === 1 ? '' : 's'}.`, 429);
    }
    const { hash } = await hashPassword(String(body.password || ''), user.pw_salt);
    if (!safeEqual(hash, user.pw_hash)) {
      const failed = user.failed + 1;
      const lockedUntil = failed >= LOCK_AFTER ? now() + LOCK_MINUTES * 60000 : 0;
      await env.DB.prepare('UPDATE users SET failed = ?, locked_until = ? WHERE id = ?')
        .bind(failed >= LOCK_AFTER ? 0 : failed, lockedUntil, user.id).run();
      return bad(generic, 401);
    }
    await env.DB.prepare('UPDATE users SET failed = 0, locked_until = 0 WHERE id = ?').bind(user.id).run();
    const { token, maxAge } = await newSession(env, user.id);
    return json({
      user: { id: user.id, username: user.username, name: user.name,
              isAdmin: !!user.is_admin, mustChange: !!user.must_change },
      teams: await teamsFor(env, user.id, !!user.is_admin),
    }, 200, { 'set-cookie': cookieHeader(token, maxAge) });
  }

  /* ---- signed in ---- */

  const me = await currentUser(request, env);

  if (path === '/logout' && method === 'POST') {
    if (me) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(me.token).run();
    return json({ ok: true }, 200, { 'set-cookie': cookieHeader('', 0) });
  }

  if (path === '/me' && method === 'GET') {
    if (!me) return json({ user: null, teams: [] });
    return json({ user: publicUser(me), teams: await teamsFor(env, me.id, me.isAdmin) });
  }

  if (!me) return bad('Please sign in.', 401);

  if (path === '/password' && method === 'POST') {
    const pErr = passwordProblem(body.password); if (pErr) return bad(pErr);
    const row = await env.DB.prepare('SELECT pw_hash, pw_salt, must_change FROM users WHERE id = ?').bind(me.id).first();
    // someone on a password an admin set for them doesn't know an old one
    if (!row.must_change) {
      const { hash } = await hashPassword(String(body.currentPassword || ''), row.pw_salt);
      if (!safeEqual(hash, row.pw_hash)) return bad('Current password is incorrect.', 401);
    }
    const { hash, salt } = await hashPassword(body.password);
    await env.DB.prepare('UPDATE users SET pw_hash = ?, pw_salt = ?, must_change = 0 WHERE id = ?')
      .bind(hash, salt, me.id).run();
    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').bind(me.id, me.token).run();
    return json({ ok: true });
  }

  /* ---- a team's content ---- */

  const tm = path.match(/^\/teams\/([A-Za-z0-9]+)$/);
  if (tm) {
    const teamId = tm[1];
    const role = await roleOn(env, teamId, me.id);
    if (!role && !me.isAdmin) return bad('You are not on that team.', 403);
    const canWrite = role === 'coach' || me.isAdmin;

    if (method === 'GET') {
      const team = await env.DB.prepare(
        `SELECT t.*, p.name AS program_name, p.logo AS program_logo, p.sport AS program_sport
           FROM teams t LEFT JOIN programs p ON p.id = t.program_id WHERE t.id = ?`).bind(teamId).first();
      if (!team) return bad('Team not found.', 404);
      const d = await env.DB.prepare('SELECT doc, rev FROM team_docs WHERE team_id = ?').bind(teamId).first();
      let doc = {};
      try { doc = d ? JSON.parse(d.doc) : {}; } catch (e) { doc = {}; }
      return json({ team: { id: team.id, name: team.name, grade: team.grade,
                            sport: team.program_sport || team.sport || 'basketball',
                            programId: team.program_id, programName: team.program_name,
                            programLogo: team.program_logo, role: role || 'admin' },
                    doc, rev: d ? d.rev : 0, canWrite });
    }

    if (method === 'PUT') {
      if (!canWrite) return bad('Only a coach can change this team.', 403);
      const text = JSON.stringify(body.doc ?? {});
      if (text.length > MAX_DOC_BYTES) return bad('That is too much data for one team.', 413);
      const cur = await env.DB.prepare('SELECT rev FROM team_docs WHERE team_id = ?').bind(teamId).first();
      const curRev = cur ? cur.rev : 0;
      // a stale writer would silently clobber a co-coach's edits
      if (typeof body.rev === 'number' && body.rev !== curRev) {
        return json({ error: 'This team was changed somewhere else. Reload to get the latest.', rev: curRev }, 409);
      }
      const nextRev = curRev + 1;
      if (cur) {
        await env.DB.prepare('UPDATE team_docs SET doc = ?, rev = ?, updated_at = ?, updated_by = ? WHERE team_id = ?')
          .bind(text, nextRev, now(), me.id, teamId).run();
      } else {
        await env.DB.prepare('INSERT INTO team_docs (team_id, doc, rev, updated_at, updated_by) VALUES (?,?,?,?,?)')
          .bind(teamId, text, nextRev, now(), me.id).run();
      }
      return json({ ok: true, rev: nextRev });
    }
  }

  // roster of people on a team — coaches and admins only
  const memMatch = path.match(/^\/teams\/([A-Za-z0-9]+)\/members$/);
  if (memMatch && method === 'GET') {
    const teamId = memMatch[1];
    const role = await roleOn(env, teamId, me.id);
    if (role !== 'coach' && !me.isAdmin) return bad('Only a coach can see this.', 403);
    const { results } = await env.DB.prepare(
      `SELECT u.id, u.name, u.username, m.role FROM memberships m
         JOIN users u ON u.id = m.user_id WHERE m.team_id = ? ORDER BY m.role DESC, u.name`).bind(teamId).all();
    return json({ members: results || [] });
  }

  /* ---- messages ----------------------------------------------------------
     Threads:
       team        announcements. Coaches post, everyone on the team reads.
       p_<userId>  a player and the coaching staff. Keyed by the player so a
                   kid has one thread, not one per coach, and every coach can
                   see it — the two-deep rule, in data form.
       c_<a>_<b>   two coaches, private to them. No player is involved, so
                   nobody else needs to be in the room.
  ------------------------------------------------------------------------ */

  const msg = path.match(/^\/teams\/([A-Za-z0-9]+)\/threads(?:\/([A-Za-z0-9_]+))?(\/messages|\/read)?$/);
  if (msg) {
    const teamId = msg[1], thread = msg[2], sub2 = msg[3];
    const myRole = await roleOn(env, teamId, me.id);
    if (!myRole && !me.isAdmin) return bad('You are not on that team.', 403);
    const iCoach = myRole === 'coach' || me.isAdmin;

    const members = (await env.DB.prepare(
      `SELECT u.id, u.name, m.role FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.team_id = ? ORDER BY m.role DESC, u.name`).bind(teamId).all()).results || [];
    const byId = Object.fromEntries(members.map(m => [m.id, m]));
    const coachPair = (a, b) => 'c_' + [a, b].sort().join('_');

    const canRead = (key) => {
      if (key === 'team') return true;
      if (key.startsWith('p_')) {
        const pid = key.slice(2);
        if (!byId[pid] || byId[pid].role === 'coach') return false;
        return iCoach || pid === me.id;
      }
      if (key.startsWith('c_')) {
        const ids = key.slice(2).split('_');
        return iCoach && ids.includes(me.id) && ids.every(i => byId[i] && byId[i].role === 'coach');
      }
      return false;
    };
    // a player may only answer a thread a coach has already opened
    const canPost = async (key) => {
      if (!canRead(key)) return false;
      if (key === 'team') return iCoach;
      if (key.startsWith('c_')) return true;
      if (key.startsWith('p_')) {
        if (iCoach) return true;
        const started = await env.DB.prepare(
          'SELECT id FROM messages WHERE team_id = ? AND thread = ? LIMIT 1').bind(teamId, key).first();
        return !!started;
      }
      return false;
    };

    if (!thread && method === 'GET') {
      const keys = ['team'];
      if (iCoach) {
        members.filter(m => m.role !== 'coach').forEach(m => keys.push('p_' + m.id));
        members.filter(m => m.role === 'coach' && m.id !== me.id).forEach(m => keys.push(coachPair(me.id, m.id)));
      } else {
        keys.push('p_' + me.id);
      }
      const rows = (await env.DB.prepare(
        `SELECT thread, MAX(created_at) AS last_at, COUNT(*) AS total FROM messages
          WHERE team_id = ? GROUP BY thread`).bind(teamId).all()).results || [];
      const lastByThread = Object.fromEntries(rows.map(r => [r.thread, r]));
      const readRows = (await env.DB.prepare(
        'SELECT thread, last_read FROM reads WHERE team_id = ? AND user_id = ?').bind(teamId, me.id).all()).results || [];
      const readByThread = Object.fromEntries(readRows.map(r => [r.thread, r.last_read]));

      const threads = [];
      for (const key of keys) {
        const seen = readByThread[key] || 0;
        const unreadRow = await env.DB.prepare(
          'SELECT COUNT(*) AS n FROM messages WHERE team_id = ? AND thread = ? AND created_at > ? AND sender_id != ?')
          .bind(teamId, key, seen, me.id).first();
        const preview = await env.DB.prepare(
          `SELECT m.body, m.created_at, u.name FROM messages m JOIN users u ON u.id = m.sender_id
            WHERE m.team_id = ? AND m.thread = ? ORDER BY m.created_at DESC LIMIT 1`).bind(teamId, key).first();
        let title = 'Whole team', kind = 'team';
        if (key.startsWith('p_')) {
          const pid = key.slice(2);
          title = iCoach ? (byId[pid] ? byId[pid].name : 'Player') : 'Coaches';
          kind = iCoach ? 'player' : 'coaches';
        } else if (key.startsWith('c_')) {
          const other = key.slice(2).split('_').find(i => i !== me.id);
          title = byId[other] ? byId[other].name : 'Coach';
          kind = 'coach';
        }
        threads.push({ key, title, kind,
          unread: unreadRow ? unreadRow.n : 0,
          lastAt: lastByThread[key] ? lastByThread[key].last_at : 0,
          preview: preview ? { body: preview.body.slice(0, 120), name: preview.name, at: preview.created_at } : null });
      }
      threads.sort((a, b) => (a.kind === 'team' ? -1 : b.kind === 'team' ? 1 : (b.lastAt - a.lastAt)));
      return json({ threads, canAnnounce: iCoach });
    }

    if (thread && sub2 === '/messages' && method === 'GET') {
      if (!canRead(thread)) return bad('Not your conversation.', 403);
      const rows = (await env.DB.prepare(
        `SELECT m.id, m.body, m.created_at, m.sender_id, u.name AS sender_name, mm.role AS sender_role
           FROM messages m JOIN users u ON u.id = m.sender_id
           LEFT JOIN memberships mm ON mm.user_id = m.sender_id AND mm.team_id = m.team_id
          WHERE m.team_id = ? AND m.thread = ? ORDER BY m.created_at LIMIT 300`).bind(teamId, thread).all()).results || [];
      return json({ messages: rows, canPost: await canPost(thread) });
    }

    if (thread && sub2 === '/messages' && method === 'POST') {
      if (!(await canPost(thread))) return bad('You cannot post here.', 403);
      const body2 = String(body.body || '').trim();
      if (!body2) return bad('Write something first.');
      if (body2.length > MAX_MESSAGE) return bad('That message is too long.');
      const id = uid(), ts = now();
      await env.DB.prepare(
        'INSERT INTO messages (id, team_id, thread, sender_id, body, created_at) VALUES (?,?,?,?,?,?)')
        .bind(id, teamId, thread, me.id, body2, ts).run();
      await env.DB.prepare(
        'INSERT OR REPLACE INTO reads (user_id, team_id, thread, last_read) VALUES (?,?,?,?)')
        .bind(me.id, teamId, thread, ts).run();
      return json({ ok: true, id, at: ts });
    }

    if (thread && sub2 === '/read' && method === 'POST') {
      if (!canRead(thread)) return bad('Not your conversation.', 403);
      await env.DB.prepare(
        'INSERT OR REPLACE INTO reads (user_id, team_id, thread, last_read) VALUES (?,?,?,?)')
        .bind(me.id, teamId, thread, now()).run();
      return json({ ok: true });
    }
  }

  /* ---- admin only ---- */

  if (path.startsWith('/admin')) {
    if (!me.isAdmin) return bad('Admins only.', 403);

    if (path === '/admin/overview' && method === 'GET') {
      const programs = (await env.DB.prepare(
        `SELECT p.id, p.name, p.sport, p.logo,
                (SELECT COUNT(*) FROM teams t WHERE t.program_id = p.id) AS teams
           FROM programs p ORDER BY p.name`).all()).results || [];
      const teams = (await env.DB.prepare(
        `SELECT t.id, t.name, t.grade, COALESCE(p.sport, t.sport) AS sport,
                t.program_id AS programId, p.name AS programName,
                (SELECT COUNT(*) FROM memberships m WHERE m.team_id = t.id) AS members,
                (SELECT COUNT(*) FROM memberships m WHERE m.team_id = t.id AND m.role = 'coach') AS coaches
           FROM teams t LEFT JOIN programs p ON p.id = t.program_id
          ORDER BY p.name, t.grade, t.name`).all()).results || [];
      const users = (await env.DB.prepare(
        `SELECT id, username, name, is_admin, must_change, created_at FROM users ORDER BY is_admin DESC, name`).all()).results || [];
      const mships = (await env.DB.prepare(
        `SELECT m.user_id, m.team_id, m.role, t.name AS team_name FROM memberships m
           JOIN teams t ON t.id = m.team_id`).all()).results || [];
      return json({
        programs,
        teams,
        users: users.map(u => ({
          id: u.id, username: u.username, name: u.name,
          isAdmin: !!u.is_admin, mustChange: !!u.must_change, created: u.created_at,
          teams: mships.filter(m => m.user_id === u.id)
                       .map(m => ({ id: m.team_id, name: m.team_name, role: m.role })),
        })),
      });
    }

    const validLogo = (v) => {
      if (v === null || v === undefined || v === '') return null;
      const str = String(v);
      if (!/^data:image\/(png|jpeg|webp|gif);base64,/.test(str)) return false;
      if (str.length > MAX_LOGO) return false;
      return str;
    };

    if (path === '/admin/programs' && method === 'POST') {
      const name = String(body.name || '').trim();
      if (name.length < 2 || name.length > 60) return bad('Give the program a name.');
      const sport = body.sport === 'lacrosse' ? 'lacrosse' : 'basketball';
      const logo = validLogo(body.logo);
      if (logo === false) return bad('That logo is not a supported image, or it is too large.');
      const id = uid();
      await env.DB.prepare('INSERT INTO programs (id, name, sport, logo, created_at) VALUES (?,?,?,?,?)')
        .bind(id, name, sport, logo, now()).run();
      return json({ program: { id, name, sport } });
    }

    const ap = path.match(/^\/admin\/programs\/([A-Za-z0-9]+)$/);
    if (ap) {
      const progId = ap[1];
      if (method === 'PATCH') {
        const name = String(body.name || '').trim();
        if (name.length < 2) return bad('Give the program a name.');
        await env.DB.prepare('UPDATE programs SET name = ? WHERE id = ?').bind(name, progId).run();
        if ('logo' in body) {
          const logo = validLogo(body.logo);
          if (logo === false) return bad('That logo is not a supported image, or it is too large.');
          await env.DB.prepare('UPDATE programs SET logo = ? WHERE id = ?').bind(logo, progId).run();
        }
        return json({ ok: true });
      }
      if (method === 'DELETE') {
        // deleting a program would orphan its teams, so make it explicit
        const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM teams WHERE program_id = ?').bind(progId).first();
        if (n.n > 0) return bad(`Move or delete this program's ${n.n} team${n.n === 1 ? '' : 's'} first.`);
        await env.DB.prepare('DELETE FROM programs WHERE id = ?').bind(progId).run();
        return json({ ok: true });
      }
    }

    if (path === '/admin/teams' && method === 'POST') {
      const name = String(body.name || '').trim();
      const grade = String(body.grade || '').trim();
      if (name.length < 2 || name.length > 60) return bad('Give the team a name.');
      const programId = String(body.programId || '');
      const prog = programId
        ? await env.DB.prepare('SELECT * FROM programs WHERE id = ?').bind(programId).first()
        : null;
      if (programId && !prog) return bad('No such program.', 404);
      const sport = prog ? prog.sport : (body.sport === 'lacrosse' ? 'lacrosse' : 'basketball');
      const id = uid(), ts = now();
      await env.DB.prepare(
        'INSERT INTO teams (id, name, grade, sport, program_id, created_by, created_at) VALUES (?,?,?,?,?,?,?)')
        .bind(id, name, grade, sport, prog ? prog.id : null, me.id, ts).run();
      await env.DB.prepare('INSERT INTO team_docs (team_id, doc, rev, updated_at, updated_by) VALUES (?,?,?,?,?)')
        .bind(id, JSON.stringify(body.doc || {}), 1, ts, me.id).run();
      // put the creator on the team so they aren't left staring at "no teams"
      await env.DB.prepare('INSERT INTO memberships (team_id, user_id, role, created_at) VALUES (?,?,?,?)')
        .bind(id, me.id, 'coach', ts).run();
      return json({ team: { id, name, grade, sport, programId: prog ? prog.id : null } });
    }

    const at = path.match(/^\/admin\/teams\/([A-Za-z0-9]+)$/);
    if (at) {
      const teamId = at[1];
      if (method === 'PATCH') {
        const name = String(body.name || '').trim();
        const grade = String(body.grade || '').trim();
        if (name.length < 2) return bad('Give the team a name.');
        await env.DB.prepare('UPDATE teams SET name = ?, grade = ? WHERE id = ?').bind(name, grade, teamId).run();
        if (body.programId) {
          const prog = await env.DB.prepare('SELECT * FROM programs WHERE id = ?').bind(body.programId).first();
          if (!prog) return bad('No such program.', 404);
          await env.DB.prepare('UPDATE teams SET program_id = ?, sport = ? WHERE id = ?')
            .bind(prog.id, prog.sport, teamId).run();
        }
        return json({ ok: true });
      }
      if (method === 'DELETE') {
        await env.DB.batch([
          env.DB.prepare('DELETE FROM team_docs WHERE team_id = ?').bind(teamId),
          env.DB.prepare('DELETE FROM memberships WHERE team_id = ?').bind(teamId),
          env.DB.prepare('DELETE FROM teams WHERE id = ?').bind(teamId),
        ]);
        return json({ ok: true });
      }
    }

    if (path === '/admin/users' && method === 'POST') {
      const username = cleanUsername(body.username);
      const name = String(body.name || '').trim();
      const uErr = usernameProblem(username); if (uErr) return bad(uErr);
      if (name.length < 2) return bad('Enter a name.');
      const pErr = passwordProblem(body.password); if (pErr) return bad(pErr);
      const clash = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
      if (clash) return bad('That username is taken.', 409);

      const { hash, salt } = await hashPassword(body.password);
      const id = uid(), ts = now();
      await env.DB.prepare(
        `INSERT INTO users (id, username, name, pw_hash, pw_salt, is_admin, must_change, created_at)
         VALUES (?,?,?,?,?,?,?,?)`)
        // the admin owns these passwords, so nobody is forced to change one
        // unless the admin explicitly asks for it
        .bind(id, username, name, hash, salt, body.isAdmin ? 1 : 0, body.mustChange === true ? 1 : 0, ts).run();
      if (body.teamId) {
        await env.DB.prepare('INSERT INTO memberships (team_id, user_id, role, created_at) VALUES (?,?,?,?)')
          .bind(body.teamId, id, body.role === 'coach' ? 'coach' : 'member', ts).run();
      }
      return json({ user: { id, username, name } });
    }

    const au = path.match(/^\/admin\/users\/([A-Za-z0-9]+)(\/membership(?:\/([A-Za-z0-9]+))?)?$/);
    if (au) {
      const targetId = au[1];
      const isMembership = !!au[2];
      const membershipTeam = au[3];
      const target = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(targetId).first();
      if (!target) return bad('No such account.', 404);

      if (!isMembership && method === 'PATCH') {
        if (typeof body.name === 'string' && body.name.trim().length >= 2) {
          await env.DB.prepare('UPDATE users SET name = ? WHERE id = ?').bind(body.name.trim(), targetId).run();
        }
        if (typeof body.password === 'string' && body.password) {
          const pErr = passwordProblem(body.password); if (pErr) return bad(pErr);
          const { hash, salt } = await hashPassword(body.password);
          await env.DB.batch([
            env.DB.prepare('UPDATE users SET pw_hash = ?, pw_salt = ?, must_change = ?, failed = 0, locked_until = 0 WHERE id = ?')
              .bind(hash, salt, body.mustChange === true ? 1 : 0, targetId),
            env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId),
          ]);
        }
        if (typeof body.isAdmin === 'boolean') {
          if (!body.isAdmin && target.is_admin) {
            const admins = await env.DB.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin = 1').first();
            if (admins.n <= 1) return bad('There has to be at least one admin.');
          }
          await env.DB.prepare('UPDATE users SET is_admin = ? WHERE id = ?').bind(body.isAdmin ? 1 : 0, targetId).run();
        }
        return json({ ok: true });
      }

      if (!isMembership && method === 'DELETE') {
        if (targetId === me.id) return bad('You cannot delete your own account.');
        if (target.is_admin) {
          const admins = await env.DB.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin = 1').first();
          if (admins.n <= 1) return bad('There has to be at least one admin.');
        }
        await env.DB.batch([
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId),
          env.DB.prepare('DELETE FROM memberships WHERE user_id = ?').bind(targetId),
          env.DB.prepare('DELETE FROM users WHERE id = ?').bind(targetId),
        ]);
        return json({ ok: true });
      }

      if (isMembership && method === 'POST') {          // add to a team, or change role
        const teamId = String(body.teamId || '');
        const role = body.role === 'coach' ? 'coach' : 'member';
        const team = await env.DB.prepare('SELECT id FROM teams WHERE id = ?').bind(teamId).first();
        if (!team) return bad('No such team.', 404);
        const existing = await roleOn(env, teamId, targetId);
        if (existing) {
          await env.DB.prepare('UPDATE memberships SET role = ? WHERE team_id = ? AND user_id = ?')
            .bind(role, teamId, targetId).run();
        } else {
          await env.DB.prepare('INSERT INTO memberships (team_id, user_id, role, created_at) VALUES (?,?,?,?)')
            .bind(teamId, targetId, role, now()).run();
        }
        return json({ ok: true });
      }

      if (isMembership && method === 'DELETE' && membershipTeam) {
        await env.DB.prepare('DELETE FROM memberships WHERE team_id = ? AND user_id = ?')
          .bind(membershipTeam, targetId).run();
        return json({ ok: true });
      }
    }
  }

  return bad('Not found.', 404);
}

/* ------------------------------------------------------------------ export */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        await ensureSchema(env);
        return await handleApi(request, env, url);
      } catch (err) {
        console.error('api error', (err && err.stack) || err);
        return bad('Something went wrong on our end.', 500);
      }
    }
    return env.ASSETS.fetch(request);
  },
};
