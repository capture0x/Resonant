<img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/7.png" style="width:130%;" />
# Resonant - OSINT AI Assistant

**AI-driven OSINT assistant.**

---

## Key Features

* **AI-Driven Intelligence**: Powered by GPT-4o (PollinationsAI) for contextual OSINT insights.
* **Integrated Search Tools**:

  * DuckDuckGo (text, image, video, news)
  * Web crawling & content extraction
  * Social media enumeration (Twitter, Instagram, GitHub)
  * YouTube metadata & comment analysis
  * Visual analysis with `image_vision`
* **User Management**: Secure registration, authentication, and session handling with Flask-Login.
* **Data Persistence**: PostgreSQL backend via SQLAlchemy and Flask-Migrate.
* **Audit Trail**: Full logging of user actions and AI responses.
* **Config Profiles**: Separate development & production settings.
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

### Install Dependencies

```bash
pip install -r requirements.txt
```

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

# 4. Configure environment variables
export DATABASE_URL=postgresql://user:password@localhost/resonant_db
export FLASK_ENV=development  # or production

# 5. Initialize database
flask db init
flask db migrate -m "Initial schema"
flask db upgrade

# 6. Run server
flask run --host=0.0.0.0 --port=5000
```

Access the UI at `http://localhost:5000`.

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
