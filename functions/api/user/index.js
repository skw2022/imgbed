import { getDatabase } from '../../utils/db';
import { hashPassword, verifyPassword } from '../../utils/password';
import { createSession, getSession, destroySession } from '../../utils/session';

export async function onRequest({ request, env }) {
  const url = new URL(request.url);

  if (url.pathname.endsWith('/register')) return register(request, env);
  if (url.pathname.endsWith('/login')) return login(request, env);
  if (url.pathname.endsWith('/me')) return me(request);
  if (url.pathname.endsWith('/logout')) return logout();

  return new Response('Not Found', { status: 404 });
}

async function register(request, env) {
  const { email, password } = await request.json();
  const db = getDatabase(env);

  const hash = await hashPassword(password);
  try {
    await db.prepare(
      `INSERT INTO users (email, password_hash) VALUES (?, ?)`
    ).bind(email, hash).run();
  } catch {
    return new Response('User exists', { status: 400 });
  }
  return json({ ok: true });
}

async function login(request, env) {
  const { email, password } = await request.json();
  const db = getDatabase(env);

  const user = await db.prepare(
    `SELECT id, email, password_hash, role FROM users WHERE email = ?`
  ).bind(email).first();

  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return new Response('Invalid credentials', { status: 401 });
  }

  const headers = new Headers();
  await createSession(headers, env, {
    id: user.id,
    email: user.email,
    role: user.role
  });

  return json({ ok: true }, headers);
}

async function me(request) {
  const user = await getSession(request);
  if (!user) return new Response('Unauthorized', { status: 401 });
  return json(user);
}

async function logout() {
  const headers = new Headers();
  await destroySession(headers);
  return json({ ok: true }, headers);
}

function json(data, headers = new Headers()) {
  headers.set('Content-Type', 'application/json');
  return new Response(JSON.stringify(data), { headers });
}
