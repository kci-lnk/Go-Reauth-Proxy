# Example Auth Server

This is a simple Authentication Server built with Bun.js.
It serves as a backend example for the global authentication feature in `go-reauth-proxy`.

## Features
-   `GET /auth`: Checks for a valid `session_id` cookie. Returns `200 OK` if valid, otherwise `401 Unauthorized`.
-   `GET /login`: Displays a simple HTML login form.
-   `POST /login`: Accepts `username=admin` & `password=admin`. Sets a `session_id` cookie (valid for 1 hour) on success, and redirects to the provided `redirect_uri` parameter (or `/` if absent).
-   `GET /logout`: Clears the `session_id` cookie and redirects to `/login` (via the proxy's `/__auth__/login` path).

## Usage

1.  **Install Bun**: [https://bun.sh](https://bun.sh) (if not installed)
2.  **Run Server**:
    From the root of the project, using Taskfile:
    ```bash
    task run:auth-server
    ```
    Or natively using Bun:
    ```bash
    bun run index.ts
    ```
    The server listens on `http://localhost:7997` by default.

## Integration with Proxy

Configure `go-reauth-proxy` to use this server globally:

1. **Set Global Auth Config**
   Point the proxy to this authentication server via the Admin API:

   ```bash
   curl -X POST http://127.0.0.1:7996/api/auth \
     -H "Content-Type: application/json" \
     -d '{
       "auth_port": 7997,
       "auth_url": "/auth",
       "login_url": "/login",
       "auth_cache_expire": 60
     }'
   ```

2. **Add a Protected Rule**
   Create a reverse proxy rule that enforces authentication (`"use_auth": true`):

   ```bash
   curl -X POST http://127.0.0.1:7996/api/rules \
     -H "Content-Type: application/json" \
     -d '[{
       "path": "/protected",
       "target": "http://localhost:8080", 
       "use_auth": true,
       "strip_path": true,
       "rewrite_html": true
     }]'
   ```
   *Note: With this setup, navigating to `http://localhost:7999/protected` will automatically redirect unauthenticated users to the login page.*
