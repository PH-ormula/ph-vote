# Ph-Vote

An interactive, anonymous voting web application built with Go. It features a WebAssembly frontend using [`go-app`](https://github.com/maxence-charriere/go-app) and an SQLite backend.

## Features

- **WebAssembly Frontend**: Responsive SPA built purely in Go.
- **Magic Link Authentication**: Users authenticate via email to ensure valid voting without needing passwords.
- **SQLite Backend**: Lightweight, file-based database for easy deployment.
- **Admin Dashboard**: For viewing results and managing the system.

## Getting Started

### Prerequisites

- [Go](https://golang.org/doc/install) 1.21 or higher.

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd ph-vote
   ```

2. Create your configuration file: Since `config.toml` contains sensitive information (like SMTP credentials), it is ignored by git. Create a `config.toml` in the project root:
   ```toml
   title = "Ph-Vote Interactive Voting"
   allowedSuffix = "@shphschool.com" # Restricts voting to this domain
   options = ["Candidate 1", "Candidate 2", "Candidate 3"]
   adminPassword = "your_secure_password"

   [smtp]
   host = "smtp.example.com"
   port = 587
   user = "vote@example.com"
   pass = "your_smtp_password"
   ```

### Building and Running

1. **Build the WebAssembly Frontend**: The frontend needs to be compiled to WebAssembly and placed in the `build/` directory so the server can serve it.
   ```bash
   mkdir -p build
   GOARCH=wasm GOOS=js go build -o build/app.wasm main_wasm.go
   ```

2. **Run the Server**: You can run the server directly:
   ```bash
   go run main_server.go
   ```
   Or build it as an executable:
   ```bash
   go build -o build/server main_server.go
   ./build/server
   ```

3. Open your browser and navigate to `http://localhost:8080`.

## Directory Structure

- `/api` - API route definitions and constants.
- `/backend` - Server logic, database management, and SMTP operations.
- `/frontend` - `go-app` WebAssembly UI components.
- `/config` - Configuration loading logic.
- `/assets` - Static assets (images, fonts, etc.).
- `/web` - Additional web assets (like CSS).
- `/build` - Destination for compiled `app.wasm` (ignored in version control).

## License

This project is licensed under the MIT License.
