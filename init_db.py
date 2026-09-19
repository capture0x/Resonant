import argparse
import os
import sys

from config import config
from models import db
from sqlalchemy import inspect

# Importing app builds nothing by itself; the app is created below once we
# know the settings are sane.
from app import create_app


def main():
    parser = argparse.ArgumentParser(description="Create the Resonant database tables.")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="DROP all existing tables first. This permanently deletes all users, chats and messages.",
    )
    parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt for --reset.")
    args = parser.parse_args()

    app = create_app(os.getenv("FLASK_ENV", "default"))

    with app.app_context():
        existing = inspect(db.engine).get_table_names()

        if args.reset:
            if not args.yes:
                target = db.engine.url.render_as_string(hide_password=True)
                print(f"This will permanently delete ALL data in: {target}")
                if input("Type YES to continue: ").strip() != "YES":
                    print("Aborted.")
                    sys.exit(1)
            db.drop_all()
            print("Existing tables dropped.")
        elif existing:
            print(f"Tables already exist ({', '.join(sorted(existing))}); nothing to do.")
            print("Use --reset if you really want to wipe and recreate them.")
            return

        db.create_all()
        print("Database tables created successfully!")


if __name__ == "__main__":
    main()
