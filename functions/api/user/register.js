export async function onRequest({ request, env }) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const { username, password } = await request.json();

  if (!username || !password) {
    return new Response("Missing params", { status: 400 });
  }

  const exists = await env.DB
    .prepare("SELECT id FROM users WHERE username = ?")
    .bind(username)
    .first();

  if (exists) {
    return new Response("User exists", { status: 409 });
  }

  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(password)
  );
  const password_hash = [...new Uint8Array(hashBuffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  await env.DB
    .prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .bind(username, password_hash)
    .run();

  return new Response(JSON.stringify({ ok: true }), {
    headers: { "Content-Type": "application/json" }
  });
}
