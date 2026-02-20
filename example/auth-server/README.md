# Example Auth Server

This is a simple Authentication Server built with Bun.js.
It serves as a backend for verifying requests proxied by `go-reauth-proxy`.

## Features
-   `GET /auth`: Returns 200 if `auth_token` cookie is valid, 401 otherwise.
-   `GET /login`: Displays a login form.
-   `POST /login`: Accepts `username=admin` & `password=admin`. Sets `auth_token` cookie on success.

## Usage

1.  **Install Bun**: [https://bun.sh](https://bun.sh) (if not installed)
2.  **Run Server**:
    ```bash
    bun index.ts
    ```
    Server listens on `http://localhost:3000`.

## Integration with Proxy

Configure `go-reauth-proxy` to use this server:

```bash
# Add Rule via Admin API
curl -X POST http://127.0.0.1:8091/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/protected",
    "target": "http://localhost:9090/protected", 
    "auth_url": "http://localhost:3000/auth",
    "login_url": "http://localhost:3000/login"
  }'
```
*Note: The `target` here is just an example. In a real scenario, you'd point to your actual backend service. If you just want to test auth, you can point target to `http://localhost:3000` (this server) and handle other paths there too.*
