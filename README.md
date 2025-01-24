# Simple File Web

A lightweight file management web application built with Go Fiber and Alpine.js, using [Templ](https://github.com/a-h/templ) for type-safe HTML templating. The app is designed to work with any S3-compatible storage service and supports login with two-factor authentication (2FA) for a single admin user.

## Features

- **Secure Login**: Protects login with TOTP-based 2FA, compatible with authenticator apps (e.g., Google Authenticator).
- **File Upload**: Enables uploading files to S3-compatible storage with real-time feedback.
- **File Listing**: Displays a responsive list of uploaded files.
- **Delete Files**: Seamlessly removes files from storage without page reloads.
- **Dynamic S3 Configuration**: Configure S3 settings (endpoint, access key, secret key, bucket name) through the web interface.
- **Type-Safe Templating with Templ**: Uses Templ for rendering HTML templates, providing improved code reliability and readability.

## Technologies Used

### Backend

- **[Go Fiber](https://gofiber.io/)**: Fast, flexible web server framework in Go.
- **[Templ](https://github.com/a-h/templ)**: Type-safe HTML templating for Go.
- **TOTP for 2FA**: Implements time-based one-time passwords (TOTP) for secure login.
- **OAuth2 (Google)**: Implements Google OAuth2 for authentication.

### Frontend

- **[Alpine.js](https://alpinejs.dev/)**: Lightweight JavaScript library for interactivity.

### Storage

- **S3-Compatible Storage**: Works with any S3-compatible storage provider.

## Setup Instructions

### Prerequisites

1. **Go**: Install [Go](https://golang.org/dl/).
2. **S3-Compatible Storage**: Ensure access to an S3-compatible storage provider.
3. **Authenticator App**: Use an authenticator app (e.g., Google Authenticator) to set up TOTP for the login.
4. **Google OAuth Setup**: Set up a Google OAuth 2.0 project to obtain your `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` credentials.

### Environment Variables

In the root directory, set up a `.env` file (or export variables in your shell) with the following configurations:

**For PowerShell (Windows):**

```powershell
$env:APP_ENV="development"
$env:PORT="3000"
$env:ORIGIN_URL="http://localhost:3000"  # Allowed origins
$env:DOWNLOAD_URL_EXPIRATION="3600"  # URL expiration time in seconds
$env:GOOGLE_CLIENT_ID=
$env:GOOGLE_CLIENT_SECRET=
```

**For Bash (Linux/Mac):**

```bash
export APP_ENV="development"
export PORT=3000
export ORIGIN_URL="http://localhost:3000"
export DOWNLOAD_URL_EXPIRATION=3600
export GOOGLE_CLIENT_ID=
export GOOGLE_CLIENT_SECRET=
```

### Running Locally

```bash
go mod tidy             # Install dependencies
go run main.go          # Start the application
```

The server will start on `http://localhost:3000`.

### Running with Docker

To quickly build and run the application in a Docker container:

1. **Build the Docker Image**

   ```bash
   docker build -t simple-file-web .
   ```
2. **Run the Docker Container**

   ```bash
   docker run -p 3000:3000 --env-file .env simple-file-web
   ```
