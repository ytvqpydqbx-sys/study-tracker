const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const COOKIE_NAME = 'st_session';
const IS_PROD = process.env.NODE_ENV === 'production';

function parseCookies(cookieHeader) {
  var cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(function(c) {
    var parts = c.trim().split('=');
    var key = decodeURIComponent(parts[0]);
    var val = parts.slice(1).join('=');
    try { cookies[key] = decodeURIComponent(val); } catch(e) { cookies[key] = val; }
  });
  return cookies;
}

function serializeCookie(name, value, options) {
  var str = name + '=' + encodeURIComponent(value);
  if (options.maxAge) str += ';Max-Age=' + options.maxAge;
  if (options.path) str += ';Path=' + options.path;
  if (options.httpOnly) str += ';HttpOnly';
  if (options.secure) str += ';Secure';
  if (options.sameSite) str += ';SameSite=' + options.sameSite;
  return str;
}

function setSessionCookie(res, session) {
  var value = JSON.stringify({
    access_token: session.access_token,
    refresh_token: session.refresh_token,
    expires_at: session.expires_at,
  });
  var cookie = serializeCookie(COOKIE_NAME, value, {
    maxAge: 60 * 60 * 24 * 7,
    path: '/',
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'Lax',
  });
  res.setHeader('Set-Cookie', cookie);
}

function clearSessionCookie(res) {
  var cookie = serializeCookie(COOKIE_NAME, '', {
    maxAge: 0,
    path: '/',
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'Lax',
  });
  res.setHeader('Set-Cookie', cookie);
}

function getSessionFromCookie(req) {
  var cookies = parseCookies(req.headers.cookie || '');
  if (!cookies[COOKIE_NAME]) return null;
  try { return JSON.parse(cookies[COOKIE_NAME]); } catch(e) { return null; }
}

async function readBody(req) {
  return new Promise(function(resolve) {
    var body = '';
    req.on('data', function(chunk) { body += chunk; });
    req.on('end', function() { resolve(body); });
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  var action = req.query.action;

  // ── セッション確認 ──
  if (action === 'session') {
    var session = getSessionFromCookie(req);
    if (!session || !session.access_token) {
      return res.status(200).json({ user: null });
    }
    try {
      var sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
        auth: { persistSession: false }
      });
      var now = Math.floor(Date.now() / 1000);
      // トークン期限切れの場合リフレッシュ
      if (session.expires_at && session.expires_at < now) {
        var refreshRes = await sb.auth.refreshSession({ refresh_token: session.refresh_token });
        if (refreshRes.error || !refreshRes.data.session) {
          clearSessionCookie(res);
          return res.status(200).json({ user: null });
        }
        setSessionCookie(res, refreshRes.data.session);
        return res.status(200).json({ user: refreshRes.data.session.user });
      }
      var userRes = await sb.auth.getUser(session.access_token);
      if (userRes.error || !userRes.data.user) {
        clearSessionCookie(res);
        return res.status(200).json({ user: null });
      }
      return res.status(200).json({ user: userRes.data.user });
    } catch(e) {
      return res.status(200).json({ user: null });
    }
  }

  // ── セッション保存 ──
  if (action === 'set-session' && req.method === 'POST') {
    var body = await readBody(req);
    var session;
    try { session = JSON.parse(body); } catch(e) {
      return res.status(400).json({ error: 'Invalid body' });
    }
    if (!session.access_token || !session.refresh_token) {
      return res.status(400).json({ error: 'Missing tokens' });
    }
    setSessionCookie(res, session);
    return res.status(200).json({ ok: true });
  }

  // ── ログアウト ──
  if (action === 'logout' && req.method === 'POST') {
    clearSessionCookie(res);
    return res.status(200).json({ ok: true });
  }

  return res.status(404).json({ error: 'Not found' });
};
