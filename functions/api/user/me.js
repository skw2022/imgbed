import { getUserFromRequest } from "../../utils/userAuth.js";

export async function onRequest({ request, env }) {
  const user = await getUserFromRequest(request, env);

  if (!user) {
    return new Response(JSON.stringify({ user: null }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  return new Response(JSON.stringify(user), {
    headers: { "Content-Type": "application/json" }
  });
}
