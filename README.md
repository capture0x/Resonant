<img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/7.png" style="width:130%;" />

# Resonant - OSINT AI Assistant

**AI-driven OSINT assistant.**

---

## Key Features

* **Self-Healing AI Backend**: On startup, Resonant automatically probes a pool of free AI providers, validates that each one can actually execute tool calls (not just chat), and keeps a shortlist of working providers. If the primary provider gets rate-limited or fails mid-conversation, requests automatically fail over to the next validated provider in the pool — no manual provider configuration needed.
* **Integrated Search Tools**:

  * DuckDuckGo (text, image, video, news)
  * Web crawling & content extraction
  * Social media enumeration (Twitter, Instagram, GitHub)
  * YouTube metadata & comment analysis
  * Visual analysis with `image_vision`
* **Reliable Multi-Tool Lookups**: Tool results (page content, search results) are automatically capped and truncated so a single OSINT lookup that chains several tools together stays within what free AI providers can accept, instead of failing on oversized requests.
* **Multi-User Ready**: Runs as a threaded server so multiple people can use it at the same time without queuing behind each other; each request's tool-call budget is isolated so concurrent users can't interfere with one another.
* **User Management**: Secure registration, authentication, and session handling with Flask-Login.
* **Data Persistence**: PostgreSQL backend via SQLAlchemy and Flask-Migrate.
* **Audit Trail**: Full logging of user actions and AI responses.
* **Config Profiles**: Separate development & production settings, loaded from a `.env` file.
* **Enterprise Logging**: RotatingFileHandler for log management.

---

## Screenshots

Below is a grid of interface screenshots (3 per row, uniform size):

<table style="width:100%; table-layout: fixed;">
  <tr>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/7.png" style="width:100%;" /></td>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/2.png" style="width:100%;" /></td>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/3.png" style="width:100%;" /></td>
  </tr>
  <tr>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/4.png" style="width:100%;" /></td>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/5.png" style="width:100%;" /></td>
    <td><img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/6.png" style="width:100%;" /></td>
    <td></td>
  </tr>
</table>

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

## Usage

1. **Register** at `/register`.
2. **Login** at `/login`.
3. **Dashboard**: Manage investigations.
4. **Chat**: Submit OSINT queries and analyze results.

---

## License

MIT License © 2025 `TMRSWRR`

> **Disclaimer:** Use responsibly and within legal and ethical guidelines. All data is sourced from publicly available channels.
