# DESCRIPTION — gosureauth (Go client SDK)

> **Read this first.** The official Go client for the sureAuth hosted auth
> service. Contract: the engine's `/api/v1/*` + `/oauth/*` (see
> `../sureauth/API.md`). One-line integration; stdlib-only; zero deps.

## What It Is

A Go library that lets a client app talk to the sureAuth engine without
hand-rolling API-key auth, JWT handling or OTP challenge flows:

```go
client := gosureauth.New()   // reads SUREAUTH_SERVER_URL + SUREAUTH_API_KEY
res, err := client.Auth(ctx, "user@example.com", "password123")
// res.Tokens OR res.Challenges — a challenge is not an error
```

## Core Behaviors

- **Zero-config via env**: `SUREAUTH_SERVER_URL` + `SUREAUTH_API_KEY`;
  explicit config via `NewWithConfig`. Credentials never hardcoded.
- **Auth result model**: `Auth`/`Login` return tokens *or* `Challenges`
  (phone_required, otp_required, email_verify_required, mfa_required).
  Challenges are driven through `SendOTP`/`VerifyOTP`/`CompletePhone`.
- **Hosted popup flow**: `LoginURL`/`CompleteLogin` for the engine's OIDC
  hosted login page (used by the dashboard quickstart).
- **Token refresh** is explicit (`TokenManager` + `RefreshToken`); session
  persistence is the app's responsibility — the lib stores nothing.
- **Typed errors**: API failures map to `*APIError{Code, Message, Status}`.
- No stdout noise; no tokens in logs.

## Contract Mirroring

Every engine endpoint ships as a typed method; field names are snake_case JSON
exactly as the engine returns them. New engine endpoint → new method + README
example (README examples must compile — they are the docs).

## Verification

- `go build ./...`, `go vet ./...`, `go test ./...` (httptest fixtures; no
  live engine needed).
- Works against the local engine (see root `Makefile` `engine` target).

## Repo Facts

- Module `github.com/medatechnology/gosureauth`; stdlib-only (keep it that way).
- Part of the sureAuth family: engine → SDKs → dashboard. Shared terms in
  `../sureauth-ecosystem.md`.
