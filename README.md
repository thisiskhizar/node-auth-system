# Node Auth System

A reusable and secure Node.js authentication system using Express, JWT, and MongoDB.

![Project Banner](./auth-hero-image.jpg)

## Features

- Email verification (via token or code)
- Login with access and refresh tokens
- Token refresh and logout
- Password reset via email
- Middleware-protected routes

## Tech Stack

- Node.js + Express
- MongoDB + Mongoose
- JWT, bcrypt, cookie-parser
- dotenv, helmet, cors, morgan

## Installation

```bash
# Clone the repo
git clone https://github.com/your-username/node-auth-system.git
cd node-auth-system

# Install dependencies
npm install

# Setup environment variables
cp .env.example .env
# Fill in the required values in .env

# Start the dev server
npm run dev
```

## API Endpoints

All endpoints are prefixed with: `/api/v1/auth`

| Method | Endpoint             | Description                          |
|--------|----------------------|--------------------------------------|
| POST   | `/register`          | Register new user                    |
| GET    | `/verify/:token`     | Verify email via token               |
| POST   | `/verify-code`       | Verify email via 6-digit code        |
| POST   | `/login`             | Login and receive tokens             |
| POST   | `/refresh-token`     | Refresh JWT access token             |
| POST   | `/logout`            | Logout and clear refresh token       |
| POST   | `/forgot-password`   | Request password reset               |
| POST   | `/reset-password/:token` | Reset password using token       |
| GET    | `/check-auth`        | Protected route — returns user info |

## Customization

- Plug into any frontend — React, Vue, mobile, etc.
- Hook up your preferred email provider in `mail.service.js`
- Extend user model or controller logic as needed

