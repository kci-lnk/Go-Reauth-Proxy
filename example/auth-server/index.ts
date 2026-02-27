const PORT = 7997;

console.log(`Auth Server running on http://localhost:${PORT}`);

const sessions = new Map<string, { expiresAt: number }>();

Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/api/auth/verify") {
      console.log("Auth request received", req.headers.get("cookie"))
      const cookie = req.headers.get("cookie") || "";
      const match = cookie.match(/session_id=([^;]+)/);
      if (match && match[1]) {
        const sessionId = match[1];
        const session = sessions.get(sessionId);
        if (session && session.expiresAt > Date.now()) {
          return new Response("Authorized", { status: 200 });
        }
      }
      return new Response("Unauthorized", { status: 401 });
    }

    if (url.pathname === "/login" && req.method === "GET") {
      return new Response(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Login</title>
          <style>
            body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; }
            .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            input { display: block; margin: 10px 0; padding: 8px; width: 100%; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0056b3; }
          </style>
        </head>
        <body>
          <div class="card">
            <h2>Login to Service</h2>
            <form method="POST" action="">
              <input type="text" name="username" placeholder="Username (admin)" required />
              <input type="password" name="password" placeholder="Password (admin)" required />
              <button type="submit">Login</button>
            </form>
          </div>
        </body>
        </html>
      `, { headers: { "Content-Type": "text/html" } });
    }

    if (url.pathname === "/login" && req.method === "POST") {
      const formData = await req.formData();
      const username = formData.get("username");
      const password = formData.get("password");

      if (username === "admin" && password === "admin") {
        const sessionId = crypto.randomUUID();
        sessions.set(sessionId, { expiresAt: Date.now() + 3600 * 1000 });
        const redirectUri = url.searchParams.get("redirect_uri") || "/";

        return new Response("Redirecting...", {
          status: 302,
          headers: {
            // Set cookie for 1 hour
            "Set-Cookie": "session_id=" + sessionId + "; Path=/; HttpOnly; Max-Age=3600",
            "Location": redirectUri
          }
        });
      }

      return new Response("Invalid credentials. <a href=''>Try again</a>", {
        status: 401,
        headers: { "Content-Type": "text/html" }
      });
    }

    if (url.pathname === "/logout") {
      const cookie = req.headers.get("cookie") || "";
      const match = cookie.match(/session_id=([^;]+)/);
      if (match && match[1]) {
        sessions.delete(match[1]);
      }
      return new Response("Logged out", {
        status: 302,
        headers: {
          "Set-Cookie": "session_id=; Path=/; Max-Age=0",
          "Location": "/__auth__/login"
        }
      });
    }

    return new Response("Not Found", { status: 404 });
  },
});
