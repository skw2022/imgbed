
import { getUserFromRequest } from "../../utils/userAuth";

/**
 * POST /api/user
 * action: register | login | logout
 */
export async function onRequestPost(context) {
  const { request, env } = context;

  const body = await request.json().catch(() => ({}));
  const { action } = body;

  /* ========= 注册 ========= */
  if (action === "register") {
    const { username, password } = body;

    if (!username || !password) {
      return json({ error: "用户名或密码不能为空" }, 400);
    }

    const exists = await env.DB
      .prepare("SELECT id FROM users WHERE username = ?")
      .bind(username)
      .first();

    if (exists) {
      return json({ error: "用户已存在" }, 409);
    }

    const passwordHash = await hashPassword(password);

    const result = await env.DB
      .prepare(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)"
      )
      .bind(username, passwordHash)
      .run();

    return json(
      {
        success: true,
        userId: result.meta.last_row_id,
      },
      201
    );
  }

  /* ========= 登录 ========= */
  if (action === "login") {
    const { username, password } = body;

    if (!username || !password) {
      return json({ error: "用户名或密码不能为空" }, 400);
    }

    const user = await env.DB
      .prepare(
        "SELECT id, password_hash FROM users WHERE username = ?"
      )
      .bind(username)
      .first();

    
    if (!user || await hashPassword(password) !== user.password_hash) {
      return json({ error: "用户名或密码错误" }, 401);
    }

    const token = crypto.randomUUID();
    const expiresAt = new Date(
      Date.now() + 7 * 24 * 3600 * 1000
    ).toISOString();

    await env.DB
      .prepare(
        "INSERT INTO user_sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
      )
      .bind(token, user.id, expiresAt)
      .run();

    return json({
      token,
      userId: user.id,
      expiresAt,
    });
  }

  /* ========= 退出 ========= */
  if (action === "logout") {
    const session = await getUserFromRequest(request, env);

    if (!session) {
      return json({ success: true });
    }

    await env.DB
      .prepare("DELETE FROM user_sessions WHERE token = ?")
      .bind(session.token)
      .run();

    return json({ success: true });
  }

  return json({ error: "未知 action" }, 400);
}

/**
 * GET /api/user
 * 当前登录用户（me）
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const session = await getUserFromRequest(request, env);

  if (!session) {
    return json({ user: null }, 401);
  }

  const user = await env.DB
    .prepare(
      "SELECT id, username, created_at FROM users WHERE id = ?"
    )
    .bind(session.user_id)
    .first();

  return json({ user });
}

/* ========= 工具函数 ========= */

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);

  const hashBuffer = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}


function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
    },
  });
}
