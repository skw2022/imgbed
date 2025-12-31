export async function onRequest({ request, env }) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/session=([^;]+)/);

  if (match) {
    await env.DB
      .prepare("DELETE FROM user_sessions WHERE id = ?")
      .bind(match[1])
      .run();
  }

  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "Set-Cookie": "session=; Path=/; Max-Age=0",
      "Content-Type": "application/json"
    }
  });
}
