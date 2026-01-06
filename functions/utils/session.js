const COOKIE_NAME = 'demo_session';

export async function createSession(headers, env, user) {
  headers.append(
    'Set-Cookie',
    `${COOKIE_NAME}=${btoa(JSON.stringify(user))}; Path=/; HttpOnly; SameSite=Lax`
  );
}

export async function getSession(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp(`${COOKIE_NAME}=([^;]+)`));
  if (!match) return null;
  try {
    return JSON.parse(atob(match[1]));
  } catch {
    return null;
  }
}

export async function destroySession(headers) {
  headers.append(
    'Set-Cookie',
    `${COOKIE_NAME}=; Path=/; Max-Age=0`
  );
}
