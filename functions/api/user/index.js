import { json } from "../../utils/response.js";
import { getUserFromRequest } from "../../utils/userAuth.js";

export async function handleUserAPI(request, env) {
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname.replace("/api/user", "");

  if (method === "POST" && path === "/register") {
    return register(request, env);
  }

  if (method === "POST" && path === "/login") {
    return login(request, env);
  }

  if (method === "POST" && path === "/logout") {
    return logout(request, env);
  }

  if (method === "GET" && path === "/me") {
    return me(request, env);
  }

  return json({ error: "Not Found" }, 404);
}
