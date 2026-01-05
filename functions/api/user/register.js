export async function onRequest({ request, env }) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const { email, password } = await request.json();

  if (!email || !password) {
    return new Response("Missing params", { status: 400 });
  }

  const exists = await env.DB
    .prepare("SELECT id FROM users WHERE email = ?")
    .bind(email)
    .first();

  if (exists) {
    return new Response("email exists", { status: 409 });
  }

  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(password)
  );
  const password_hash = [...new Uint8Array(hashBuffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  await env.DB
    .prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)")
    .bind(email, password_hash)
    .run();

  return new Response(JSON.stringify({ ok: true }), {
    headers: { "Content-Type": "application/json" }
  });
}
