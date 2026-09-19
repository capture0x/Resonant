<img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/screenshots/7.png" style="width:130%;" />

# Resonant — OSINT AI Assistant

Resonant is a self-hosted web application that pairs a tool-using AI agent with a set of OSINT (Open-Source Intelligence) utilities — web search, social profile lookups, page crawling, image analysis, and YouTube metadata/comment retrieval — behind a standard user-authenticated chat interface.

---

## Table of Contents

- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [Screenshots](#screenshots)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Security & Ethical Use](#security--ethical-use)
- [License](#license)

---

## Key Features

* **Self-Healing AI Backend**: On startup, Resonant probes a pool of free AI providers, validates that each one can actually execute tool calls (not just chat), and keeps a shortlist of working providers. If the primary provider gets rate-limited or fails mid-conversation, requests automatically fail over to the next validated provider — no manual provider configuration needed.
* **Integrated OSINT Tools**:
  * DuckDuckGo search (text, images, videos, news)
  * Web crawling & main-content extraction
  * Social media enumeration (Twitter, Instagram, GitHub)
  * YouTube metadata & comment retrieval
  * Image analysis via `image_vision`
* **Reliable Multi-Tool Lookups**: Tool output (page content, search results) is automatically capped and truncated so a lookup chaining several tools together stays within what free AI providers can accept, instead of failing on oversized requests.
* **Multi-User Ready**: Runs as a threaded server so multiple people can use it concurrently without queuing behind one another; each request's tool-call budget is isolated per request, so concurrent users can't interfere with each other.
* **User Management**: Registration, authentication, and session handling via Flask-Login, with hashed passwords (Werkzeug).
* **Data Persistence**: PostgreSQL backend via SQLAlchemy, with Flask-Migrate available for schema migrations.
* **Audit Trail**: Rotating file logs of user actions and AI responses.
* **Environment-Based Config**: Separate development/production settings loaded from a `.env` file.

---

## How It Works

1. **Provider discovery** — at startup, `main.py` scans available free AI providers (via [`g4f`](https://github.com/gpt4free/g4f)), running two checks per candidate: a cheap text-completion test, then a real multi-tool-call test using the agent's actual system prompt and tool set. Only providers that pass both, and don't leak raw tool-call syntax or return disguised rate-limit notices, are kept.
2. **Provider pool & failover** — several validated providers are kept in a pool rather than just one. If the primary provider fails or gets rate-limited during a real request, the app automatically retries with the next validated provider before falling back to a plain (toolless) response.
3. **Tool execution** — the agent (built with [pydantic-ai](https://ai.pydantic.dev/)) calls into OSINT tools as needed (search, profile lookup, page visit, etc.). Each tool result is size-capped so a chain of several tool calls in one conversation doesn't exceed what a free-tier provider can accept in a single request.
4. **Persistence** — chats and messages are stored per-user in PostgreSQL; the web UI (Flask + Flask-Login) reads/writes through SQLAlchemy models.

---

## Screenshots

<table style="width:100%; table-layout: fixed;">
  <tr>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/screenshots/7.png" style="width:100%;" /></td>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/screenshots/2.png" style="width:100%;" /></td>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/screenshots/3.png" style="width:100%;" /></td>
  </tr>
  <tr>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/screenshots/4.png" style="width:100%;" /></td>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/screenshots/5.png" style="width:100%;" /></td>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/screenshots/6.png" style="width:100%;" /></td>
  </tr>
</table>

---

## Tech Stack

| Layer          | Technology                                  |
|----------------|----------------------------------------------|
| Web framework  | Flask, Flask-Login, Flask-Migrate            |
| AI agent       | pydantic-ai + g4f (free-tier model access)   |
| Database       | PostgreSQL, SQLAlchemy                       |
| Search/tools   | duckduckgo_search, stealth_requests, MainContentExtractor |
| Frontend       | Jinja2 templates                             |

---

## Prerequisites

* **Python** 3.10+
* **PostgreSQL** 12+

---

## Installation & Setup

```bash
# 1. Clone repository
git clone https://github.com/capture0x/Resonant.git
cd Resonant

# 2. Virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python packages
pip install -r requirements.txt

# 4. Create the PostgreSQL database and user
sudo -u postgres psql -c "CREATE ROLE myuser LOGIN PASSWORD 'mypassword';"
sudo -u postgres psql -c "CREATE DATABASE resonant_db OWNER myuser;"

# 5. Configure environment variables
cp .env.example .env
# then edit .env and set SECRET_KEY / DATABASE_URL to match step 4

# 6. Initialize the database schema
python init_db.py

# 7. Run server
python app.py
```

Access the UI at `http://localhost:5000`.

> A standalone CLI mode is also available for quick testing without the web UI: `python main.py`.

---

## Configuration

Environment variables are loaded from `.env` (see `.env.example`):

| Variable        | Description                                              |
|-----------------|------------------------------------------------------------|
| `FLASK_ENV`     | `development` or `production`                             |
| `SECRET_KEY`    | Flask session signing key — use a long random value       |
| `DATABASE_URL`  | PostgreSQL connection string                               |
| `REDIS_URL`     | Reserved for future use                                    |

---

## Usage

1. **Register** at `/register`.
2. **Login** at `/login`.
3. **Dashboard**: create, open, and delete investigations (chats).
4. **Chat**: submit OSINT queries in natural language; the agent decides which tools to call.

---

## Troubleshooting

* **`SQLALCHEMY_DATABASE_URI` not set / connection refused** — make sure PostgreSQL is running and `DATABASE_URL` in `.env` is correct.
* **"AI Service is currently unavailable"** — all probed free providers failed at startup; this is a limitation of the free-tier backend, not a crash. Restart the app to re-probe, or check your network's outbound access to the provider endpoints.
* **Slow first response** — the first request after startup triggers provider discovery (multiple network round-trips); subsequent requests reuse the validated pool and are much faster.

---

## Security & Ethical Use

Resonant only surfaces information that is already publicly accessible through the platforms and search engines it queries (DuckDuckGo, public GitHub API, public web pages). It performs no authentication bypass, scraping of private/gated content, or automated account access.

You are responsible for using this tool in compliance with the terms of service of any third-party platform you query, and with the laws and regulations applicable in your jurisdiction. Use it only for legitimate, authorized OSINT research.

---

## License

Licensed under the [Apache License 2.0](LICENSE) © 2025 `TMRSWRR`.
