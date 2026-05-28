import { createClient } from '@supabase/supabase-js';
import { serialize, parse } from 'cookie';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const COOKIE_NAME = 'st_session';
const IS_PROD = process.env.NODE_ENV === 'production';

// セッションをHttpOnly Cookieにセット
function setSessionCookie(res, session) {
  const cookie = serialize(COOKIE_NAME, JSON.stringify({
    access_token: session.access_token,
    refresh_token: session.refresh_token,
    expires_at: session.expires_at,
  }), {
    httpOnly: true,       // JSから読めない（XSS対策）
    secure: IS_PROD,      // HTTPS必須（本番のみ）
    sameSite: 'strict',   // CSRF対策
    path: '/',
    maxAge: 60 * 60 * 24 * 7, // 7日
  });
  res.setHeader('Set-Cookie', cookie);
}

// セッションCookieを削除
function clearSessionCookie(res) {
  const cookie = serialize(COOKIE_NAME, '', {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'strict',
    path: '/',
    maxAge: 0,
  });
  res.setHeader('Set-Cookie', cookie);
}

// Cookieからセッションを取得
function getSessionFromCookie(req) {
  const cookies = parse(req.headers.cookie || '');
  if (!cookies[COOKIE_NAME]) return null;
  try {
    return JSON.parse(cookies[COOKIE_NAME]);
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  // CORS設定
  res.setHeader('Content-Type', 'application/json');

  const { action } = req.query;

  // ── セッション確認 ──
  if (action === 'session') {
    const session = getSessionFromCookie(req);
    if (!session) {
      return res.status(200).json({ user: null });
    }
    // トークンの有効期限確認
    const now = Math.floor(Date.now() / 1000);
    if (session.expires_at && session.expires_at < now) {
      // リフレッシュ試行
      const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
      const { data, error } = await sb.auth.refreshSession({
        refresh_token: session.refresh_token,
      });
      if (error || !data.session) {
        clearSessionCookie(res);
        return res.status(200).json({ user: null });
      }
      setSessionCookie(res, data.session);
      return res.status(200).json({ user: data.session.user });
    }
    // 有効なセッション：ユーザー情報だけ返す（トークンは返さない）
    const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
    const { data, error } = await sb.auth.getUser(session.access_token);
    if (error || !data.user) {
      clearSessionCookie(res);
      return res.status(200).json({ user: null });
    }
    return res.status(200).json({ user: data.user });
  }

  // ── セッション保存（Googleログイン後） ──
  if (action === 'set-session' && req.method === 'POST') {
    let body = '';
    await new Promise((resolve) => {
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', resolve);
    });
    let session;
    try {
      session = JSON.parse(body);
    } catch {
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
}
