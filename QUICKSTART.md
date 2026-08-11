# Quickstart — Go backend (recommended)

> **This is the recommended way to integrate sureAuth: your Go backend holds
> the app API key and talks to the engine directly (mode 1).** Your frontend
> never touches the engine — it talks to *your* backend, which keeps the API
> key out of the browser (security first).
>
> Full contract: [`../sureauth/docs/CLIENT_GUIDE.md`](../sureauth/docs/CLIENT_GUIDE.md)

```
Browser (your SPA) ──▶ your Go backend ──▶ sureAuth engine
                      (gosureauth, API key here)
```

## 1. Install

```bash
go get github.com/medatechnology/sureauth-go
```

## 2. Configure

Env (or your config):

```bash
SUREAUTH_SERVER_URL=https://auth.sureauth.app   # the engine
SUREAUTH_API_KEY=your-app-api-key                # from the cloud, shown once
```

The client reads both automatically:

```go
import "github.com/medatechnology/sureauth-go"

c, err := sureauth.New()   // reads SUREAUTH_SERVER_URL + SUREAUTH_API_KEY
```

## 3. Your user table (create once)

```sql
CREATE TABLE users (
    id                   BIGSERIAL PRIMARY KEY,      -- your format (int/uuid)
    sureauth_app_user_id TEXT UNIQUE NOT NULL,       -- ← the bridge to sureAuth
    email                TEXT UNIQUE,
    display_name         TEXT,
    created_at           TIMESTAMPTZ DEFAULT now()
);
```

## 4. Register + save the profile (your backend)

```go
// POST /api/register  (your route)
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
        Name     string `json:"name"`
    }
    json.NewDecoder(r.Body).Decode(&req)

    res, err := s.auth.Register(r.Context(), sureauth.AuthRequest{
        Email: req.Email, Password: req.Password,
    })
    if err != nil { http.Error(w, err.Error(), 400); return }
    if len(res.Challenges) > 0 {
        // e.g. fields_required — ask for the missing fields, then
        // s.auth.CompleteMembership(ctx, ...)
        json.NewEncoder(w).Encode(res.Challenges); return
    }

    // Save YOUR profile, keyed by the sureAuth id:
    var userID int64
    s.db.QueryRow(`INSERT INTO users (sureauth_app_user_id, email, display_name)
                   VALUES ($1,$2,$3) RETURNING id`,
        res.AppUser.ID, req.Email, req.Name).Scan(&userID)

    // Now issue YOUR session to the frontend (cookie/JWT) + return userID
    json.NewEncoder(w).Encode(map[string]any{"user_id": userID, "ok": true})
}
```

## 5. Login + map back

```go
// POST /api/login
res, err := s.auth.Auth(r.Context(), identifier, credential)
if err != nil { http.Error(w, "invalid credentials", 401); return }
if len(res.Challenges) > 0 { /* OTP/verify step — send/verify OTP */ }

// Find YOUR user by the sureAuth id:
var u User
s.db.QueryRow(`SELECT * FROM users WHERE sureauth_app_user_id = $1`, res.AppUser.ID).Scan(&u)
// issue your session cookie, return u
```

## 6. Validate tokens on protected routes

```go
// middleware for /api/me, /api/orders, ...
func (s *Server) requireUser(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        token := bearer(r)
        claims, err := s.auth.ValidateToken(r.Context(), token)
        if err != nil { http.Error(w, "unauthorized", 401); return }
        // claims.AppUserID → your users.sureauth_app_user_id
        next(w, r)
    }
}
```

## 7. Account management (users change their own credentials)

```go
s.auth.Forgot(ctx, sureauth.ForgotRequest{Identifier: email, Channel: "otp"})   // or "magic_link"
s.auth.Reset(ctx, sureauth.ResetRequest{Identifier: email, Code: code, NewPassword: pw})
s.auth.ChangePassword(ctx, accessToken, sureauth.ChangePasswordRequest{CurrentPassword: old, NewPassword: pw})
s.auth.ChangeIdentifier(ctx, accessToken, sureauth.ChangeIdentifierRequest{NewEmail: newEmail, OTPCode: code})
s.auth.UnlinkGoogle(ctx, accessToken, sureauth.UnlinkGoogleRequest{})
```

## 8. Google SSO

Google SSO starts in the **browser** (redirect/popup to the engine), so your
backend only handles the callback: the engine redirects to your
`redirect_uri` with a code; your backend exchanges it:

```go
// POST /api/auth/google/callback?code=...
res, err := s.auth.CompleteLogin(r.Context(), code, redirectURI)
// res.AppUser.ID → your mapping column (create the profile if new)
```

(If you'd rather keep everything server-side: `s.auth.LinkGoogle` returns the
SSO URL for a signed-in user to attach Google.)

## What you wrote

One table (`users` + one column) and ~40 lines of Go. Everything else —
hashing, OTP, verification, refresh, Google, cross-app identity — is the
engine's.

Full API reference: [`sureauth/API.md`](../sureauth/API.md) · SDK reference:
[`client.go`](client.go)
