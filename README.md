# goSureAuth

Official Go client for the **sureAuth** hosted auth service. One-line
integration: the library reads your credentials from the environment and
handles API-key auth, project scoping, OTP challenges and token refresh —
you never hardcode credentials.

## Install

```bash
go get github.com/medatechnology/goSureAuth@latest
```

## Quick start (server-side)

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/medatechnology/goSureAuth"
)

func main() {
	// Zero-config: reads SUREAUTH_SERVER_URL + SUREAUTH_API_KEY from env.
	client, err := gosureauth.New()
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	// One-line sign-in with your project's configured login method
	// (email/phone/username × password/pin/otp).
	auth, err := client.Auth(ctx, "user@example.com", "SecurePassword123!")
	if err != nil {
		log.Fatal(err)
	}

	// The server may ask for more steps (OTP, phone, MFA):
	for _, ch := range auth.Challenges {
		switch ch.Type {
		case gosureauth.ChallengeOTPRequired:
			_, _ = client.SendOTP(ctx, gosureauth.SendOTPRequest{Identifier: ch.Field, Purpose: "login"})
			auth, err = client.VerifyOTP(ctx, ch.Field, "123456")
		case gosureauth.ChallengePhoneRequired:
			auth, err = client.CompletePhone(ctx, gosureauth.CompletePhoneRequest{Email: ch.Field, Phone: "+62812..."})
		}
	}

	fmt.Println("Access token:", auth.AccessToken)
	me, _ := client.Me(ctx, auth.AccessToken)
	fmt.Println("User:", me.AppUserID)
}
```

## Hosted login (popup/redirect)

```go
url, _ := client.LoginURL(ctx, "https://app.com/auth/callback")
// redirect the browser to url; after sign-in the engine redirects back with ?code=...
auth, err := client.CompleteLogin(ctx, code, "https://app.com/auth/callback")
```

## Token refresh

```go
tm := gosureauth.NewTokenManager(client, auth.AccessToken, auth.RefreshToken, auth.ExpiresIn)
tm.OnRefresh(func(newToken string) { /* persist */ })
token, _ := tm.GetAccessToken(ctx)
```

## Config

| Env | Meaning |
|-----|---------|
| `SUREAUTH_SERVER_URL` | Engine URL (default `https://auth.sureauth.app`) |
| `SUREAUTH_API_KEY` | Your project API key (created in the dashboard) |

Or `gosureauth.NewWithConfig(gosureauth.Config{...})`.

## License

MIT
