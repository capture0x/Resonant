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

All images are the same display size (width=800px).

|                                      Landing Page & Core Module                                      |                                          Authentication Flow                                         |                                           Query Submission                                           |                                          Real-Time Analysis                                          |                                         Investigation Summary                                        |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| <img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/1.png" width="1000" /> | <img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/2.png" width="1000" /> | <img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/3.png" width="1000" /> | <img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/4.png" width="1000" /> | <img src="https://raw.githubusercontent.com/capture0x/Resonant/refs/heads/main/5.png" width="1000" /> |

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

## Contributing

1. Fork this repo.
2. Create a branch: `git checkout -b feature/your-feature`.
3. Commit: `git commit -m "Add feature"`.
4. Push: `git push origin feature/your-feature`.
5. Open a Pull Request.

---

## License

MIT License © 2025 `TMRSWRR`

> **Disclaimer:** Use responsibly and within legal and ethical guidelines. All data is sourced from publicly available channels.

