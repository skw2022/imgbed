export async function onRequest({ request, env }) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const { username, password } = await request.json();

  const user = await env.DB
    .prepare("SELECT * FROM users WHERE username = ?")
    .bind(username)
    .first();

  if (!user) {
    return new Response("Invalid credentials", { status: 401 });
  }

  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(password)
  );
  const password_hash = [...new Uint8Array(hashBuffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  if (password_hash !== user.password_hash) {
    return new Response("Invalid credentials", { status: 401 });
  }

  const sessionId = crypto.randomUUID();
  const expires = Date.now() + 7 * 86400 * 1000;

  await env.DB
    .prepare(
      "INSERT INTO user_sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
    )
    .bind(sessionId, user.id, expires)
    .run();

  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "Set-Cookie": `session=${sessionId}; Path=/; HttpOnly; SameSite=Lax`,
      "Content-Type": "application/json"
    }
  });
}
