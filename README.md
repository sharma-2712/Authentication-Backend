# Authentication API

Node.js authentication service built with Express, MongoDB, and Mongoose. It supports user registration, email OTP verification, login, refresh tokens, logout, and logout from all devices.

## Features

- User registration with hashed passwords.
- OTP-based email verification.
- Login with JWT access tokens and refresh tokens.
- Refresh token rotation and session tracking.
- Logout and logout from all devices.
- Gmail OAuth2 email delivery with Nodemailer.

## Tech Stack

- Node.js
- Express 5
- MongoDB
- Mongoose
- JSON Web Token
- Nodemailer
- Morgan
- Cookie Parser

## Project Structure

```text
server.js
src/
  app.js
  config/
    config.js
    database.js
  controller/
    auth.controller.js
  models/
    otp.model.js
    session.model.js
    user.model.js
  routes/
    auth.route.js
  service/
    email.service.js
  utils/
    utils.js
```

## Setup

1. Install dependencies.

```bash
npm install
```

2. Create a `.env` file in the project root and set the required values.

```env
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
GOOGLE_CLIENT_ID=your_google_oauth_client_id
GOOGLE_CLIENT_SECRET=your_google_oauth_client_secret
GOOGLE_REFRESH_TOKEN=your_google_oauth_refresh_token
GOOGLE_USER=your_gmail_address
```

3. Start the server.

```bash
npm run dev
```

The app listens on port `3000`.

## API Base Path

All routes are mounted under:

```text
/api/auth
```

## Endpoints

### Register

- Method: `POST`
- Path: `/api/auth/register`

Request body:

```json
{
  "username": "john",
  "email": "john@example.com",
  "password": "secret123"
}
```

Behavior:

- Creates a new user with a SHA-256 hashed password.
- Generates a 6-digit OTP.
- Stores a hashed OTP in the database.
- Sends the OTP by email.

### Login

- Method: `POST`
- Path: `/api/auth/login`

Request body:

```json
{
  "email": "john@example.com",
  "password": "secret123"
}
```

Behavior:

- Rejects unverified users.
- Validates the password hash.
- Creates a refresh token and stores its hash in the session collection.
- Returns a signed access token in the response payload.
- Sets the refresh token in an HTTP-only cookie.

### Get Current User

- Method: `GET`
- Path: `/api/auth/get-me`

Status:

- The controller is present, but the handler is not implemented yet.

### Refresh Access Token

- Method: `GET`
- Path: `/api/auth/refresh-token`

Behavior:

- Reads the refresh token from the cookie.
- Verifies the token and checks the stored session hash.
- Rotates the refresh token and returns a new access token.

### Logout

- Method: `GET`
- Path: `/api/auth/logout`

Behavior:

- Reads the refresh token from the cookie.
- Marks the matching session as revoked.
- Clears the refresh token cookie.

### Logout From All Devices

- Method: `GET`
- Path: `/api/auth/logout-all`

Behavior:

- Reads the refresh token from the cookie.
- Revokes all active sessions for the user.
- Clears the refresh token cookie.

### Verify Email

- Method: `GET`
- Path: `/api/auth/verify-email`

Request body:

```json
{
  "email": "john@example.com",
  "otp": "123456"
}
```

Behavior:

- Hashes the provided OTP.
- Looks up the OTP record by email and hashed OTP.
- Marks the user as verified.
- Deletes OTP records for that user.

## Data Models

### User

- `username` - unique string
- `email` - unique string
- `password` - hashed string
- `verified` - boolean flag, defaults to `false`

### OTP

- `email` - user email
- `user` - user reference
- `otpHash` - hashed OTP value

### Session

- `user` - user reference
- `refreshTokenHash` - hashed refresh token
- `ip` - client IP address
- `userAgent` - browser or client user agent
- `revoked` - boolean flag, defaults to `false`

## Email Delivery

Email sending uses Gmail OAuth2 through Nodemailer. The service verifies the transport on startup and sends both plain-text and HTML OTP messages.

## Notes

- Passwords are hashed with SHA-256 in the current implementation.
- Refresh tokens are stored only as hashes in the database.
- The router currently registers `refresh-token`, `logout`, `logout-all`, and `verify-email` as `GET` routes, even though some controller comments mention `POST`.
- `get-me` is not implemented yet.

## Scripts

- `npm run dev` - start the API with Nodemon.

## License

No license has been specified in the project yet.