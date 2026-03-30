# Google OAuth

Google OAuth lets users log in with their Google account. This module handles the authorization flow without any extra dependencies.

## Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials) and create an OAuth 2.0 Client ID.
2. Set the authorized redirect URI (e.g. `http://localhost:8080/auth/google/callback`).
3. Copy the Client ID and Client Secret.

## Usage

### Initialize

```go
err := a.Google_init("YOUR_CLIENT_ID", "YOUR_CLIENT_SECRET", "http://localhost:8080/auth/google/callback")
```

### Step 1: Redirect user to Google

```go
authURL, err := a.Google_auth_url("random-state-string")
// redirect user to authURL
```

### Step 2: Handle the callback

When Google redirects back with a `code` parameter:

```go
guser, err := a.Google_exchange(code)
// guser.ID, guser.Email, guser.Name are now available
```

### Step 3: Link or login

For new users, just call Link_google. It will automatically create the user in the users table:

```go
err = a.Link_google(guser, guser.Email)
```

This means the OAuth user can now use all existing functions like permissions, roles, and JWT tokens.

For returning users, just look them up:

```go
userID, err := a.Login_google(guser.ID)
```

## Database

This creates an `oauth_users` table automatically:

| Column      | Type      | Description                              |
|-------------|-----------|------------------------------------------|
| provider    | TEXT      | Always "google" for this flow            |
| provider_id | TEXT      | Google user ID                           |
| user_id     | TEXT      | References users(user_id)                |
| email       | TEXT      | Google email                             |
| name        | TEXT      | Google display name                      |
| created_at  | TIMESTAMP | When the link was created                |

Primary key is `(provider, provider_id)`, so the same table can support other OAuth providers in the future.
