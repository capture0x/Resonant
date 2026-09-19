import os
import re
import secrets
import threading
import time
import logging
import json
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
from datetime import datetime

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError

from config import config, PLACEHOLDER_SECRETS
from models import db, User, Chat, Message
from pydantic_ai.messages import ModelRequest, ModelResponse, SystemPromptPart, UserPromptPart, TextPart
from pydantic_ai.models import ModelSettings


class RateLimiter:
    """Small in-memory sliding-window limiter (per process). Enough to blunt
    password guessing, signup spam and free-provider quota abuse without
    adding a Redis dependency; put a real limiter in front of a multi-worker
    deployment."""

    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, q, window, now):
        while q and now - q[0] > window:
            q.popleft()

    def blocked(self, key, limit, window):
        now = time.time()
        with self._lock:
            q = self._hits[key]
            self._prune(q, window, now)
            return len(q) >= limit

    def hit(self, key, window):
        now = time.time()
        with self._lock:
            q = self._hits[key]
            self._prune(q, window, now)
            q.append(now)

    def clear(self, key):
        with self._lock:
            self._hits.pop(key, None)


limiter = RateLimiter()
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
LOGIN_MAX_FAILURES, LOGIN_WINDOW = 5, 15 * 60
REGISTER_MAX, REGISTER_WINDOW = int(os.getenv("REGISTER_MAX_PER_HOUR", "10")), 60 * 60
AI_MESSAGES_PER_HOUR = int(os.getenv("AI_MESSAGES_PER_HOUR", "30"))


def create_app(config_name='default'):
    app = Flask(__name__)

    # Load base config
    app.config.from_object(config[config_name])
    # Override DB URI if environment variable provided
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL',
        app.config.get('SQLALCHEMY_DATABASE_URI')
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    if not app.config.get('SQLALCHEMY_DATABASE_URI'):
        raise RuntimeError(
            "DATABASE_URL is not set. Copy .env.example to .env and point it "
            "at your PostgreSQL database."
        )

    if app.config.get('SECRET_KEY', '') in PLACEHOLDER_SECRETS:
        if config_name == 'production':
            raise RuntimeError(
                "SECRET_KEY is missing or still a placeholder. Set it in .env to "
                "a long random value, e.g. python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        # Development only: throwaway key, so sessions reset on every restart.
        app.config['SECRET_KEY'] = secrets.token_hex(32)

    CSRFProtect(app)

    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)

    # Setup Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except Exception:
            return None

    # Setup logging
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler(
            'logs/Resonant.log',
            maxBytes=10240,
            backupCount=10
        )
        file_handler.setFormatter(
            logging.Formatter(app.config['LOG_FORMAT'])
        )
        file_handler.setLevel(logging.getLevelName(app.config['LOG_LEVEL']))
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.getLevelName(app.config['LOG_LEVEL']))
        app.logger.info('Resonant startup')

    # Routes
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db.session.remove()
        
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            ip = request.remote_addr or 'unknown'
            if limiter.blocked(f'register:{ip}', REGISTER_MAX, REGISTER_WINDOW):
                flash('Too many sign-ups from this address. Try again later.')
                return render_template('register.html'), 429

            username = (request.form.get('username') or '').strip()
            password = request.form.get('password') or ''
            confirm = request.form.get('confirm_password')

            if not USERNAME_RE.match(username):
                flash('Username must be 3-32 characters: letters, numbers, dot, dash or underscore')
                return redirect(url_for('register'))
            if not 8 <= len(password) <= 128:
                flash('Password must be between 8 and 128 characters')
                return redirect(url_for('register'))
            if confirm is not None and confirm != password:
                flash('Passwords do not match')
                return redirect(url_for('register'))

            if User.query.filter_by(username=username).first():
                flash('Username already exists')
                return redirect(url_for('register'))

            new_user = User(
                username=username,
                password_hash=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            # Only successful sign-ups count toward the limit: validation
            # mistakes don't create accounts, so they shouldn't lock people out.
            limiter.hit(f'register:{ip}', REGISTER_WINDOW)
            app.logger.info(f'New user registered: {username}')
            return redirect(url_for('login'))

        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = (request.form.get('username') or '').strip()
            password = request.form.get('password') or ''
            ip = request.remote_addr or 'unknown'
            user_key = f'login:{ip}:{username.lower()}'
            ip_key = f'login-ip:{ip}'

            if (limiter.blocked(user_key, LOGIN_MAX_FAILURES, LOGIN_WINDOW)
                    or limiter.blocked(ip_key, LOGIN_MAX_FAILURES * 4, LOGIN_WINDOW)):
                app.logger.warning(f'Login rate limit hit for user: {username} from {ip}')
                flash('Too many failed attempts. Try again in a few minutes.')
                return render_template('login.html'), 429

            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                limiter.clear(user_key)
                login_user(user)
                app.logger.info(f'User logged in: {username}')
                return redirect(url_for('dashboard'))

            limiter.hit(user_key, LOGIN_WINDOW)
            limiter.hit(ip_key, LOGIN_WINDOW)
            flash('Invalid username or password')
            app.logger.warning(f'Failed login attempt for user: {username}')

        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        chats = Chat.query.filter_by(
            user_id=current_user.id
        ).order_by(Chat.created_at.desc()).all()
        return render_template('dashboard.html', chats=chats)

    @app.route('/chat/new', methods=['POST'])
    @login_required
    def new_chat():
        try:
            chat = Chat(user_id=current_user.id)
            db.session.add(chat)
            db.session.commit()
            return jsonify({'chat_id': chat.id})
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating chat: {e}')
            return jsonify({'error': 'Could not create chat'}), 500

    @app.route('/chat/<chat_id>')
    @login_required
    def chat_view(chat_id):
        chat = Chat.query.get_or_404(chat_id)
        if chat.user_id != current_user.id:
            return redirect(url_for('dashboard'))
        return render_template('chat.html', chat=chat)

    def get_ai_response(user_message, chat_history):
        """Get AI response with multiple fallback mechanisms"""
        # A bare email address gets a deterministic, structured report built
        # straight from the open-source lookups: nothing in it can be invented
        # by a model, and it doesn't wait for AI-provider discovery.
        from email_intel import EMAIL_RE, gather_email_intel, format_email_report
        if EMAIL_RE.match(user_message.strip()):
            try:
                return format_email_report(gather_email_intel(user_message.strip(), deep=True))
            except Exception as e:
                app.logger.warning(f"Email report failed, falling back to the agent: {e}")

        try:
            # Try to import from main
            from main import agent as main_agent
            from main import all_tools, reset_tool_counter, PROVIDER_POOL, _looks_like_provider_failure, classify_identifier, run_recon
            from pydantic_ai.exceptions import UnexpectedModelBehavior

            # Check if agent exists
            if main_agent is None:
                raise ValueError("AI agent not initialized")

            # Build message history
            history = []
            for msg in chat_history[-10:]:  # Limit to last 10 messages
                if msg.is_user:
                    history.append(
                        ModelRequest(parts=[UserPromptPart(content=msg.content)])
                    )
                else:
                    history.append(
                        ModelResponse(parts=[TextPart(content=msg.content)])
                    )

            # A bare identifier (username/email/domain/IP) gets a guaranteed
            # baseline investigation done in code, in parallel, instead of
            # trusting the model to choose enough tools on its own.
            agent_prompt = user_message
            kind = classify_identifier(user_message)
            if kind:
                identifier = user_message.strip().lstrip('@')
                recon = run_recon(identifier, kind)
                agent_prompt = (
                    f"{user_message}\n\n"
                    f"[Live OSINT results already gathered automatically for this {kind}. "
                    f"Write a thorough, well-structured report based on these real results, "
                    f"and use your tools to dig deeper into anything interesting (profiles, "
                    f"domains, emails found). Do not invent facts that are not in the "
                    f"results or from tools.]\n{json.dumps(recon, ensure_ascii=False)}"
                )

            def _try_agent(candidate_agent):
                # The tool-call counter is a single global shared by every
                # request; without resetting it here, users would permanently
                # lose tool access once 5 tool calls had ever been made
                # across the whole app's lifetime.
                reset_tool_counter()
                result = candidate_agent.run_sync(agent_prompt, message_history=history)
                output = str(result.output)
                if _looks_like_provider_failure(output):
                    # Either the provider stopped actually executing tool
                    # calls and started typing them out as text, or it
                    # returned an HTTP-200 rate-limit/error notice as if it
                    # were a genuine answer. Either way, don't show it to
                    # the user as if it were real.
                    raise RuntimeError("Provider returned a leaked function-call or rate-limit/error notice")
                return output

            # Free providers routinely hit per-IP rate limits or transient
            # errors, so try every provider main.py already validated at
            # startup (PROVIDER_POOL) before giving up on a real answer.
            candidate_pool = PROVIDER_POOL or [{"provider": None, "agent": main_agent}]
            last_error = None
            for candidate in candidate_pool:
                try:
                    return _try_agent(candidate["agent"])
                except Exception as e:
                    provider_name = candidate["provider"].__name__ if candidate["provider"] else "primary"
                    app.logger.warning(f"Provider {provider_name} failed: {e}")
                    last_error = e

            # Every pooled provider failed; try one last direct (toolless)
            # API call before giving the user a canned response.
            try:
                import g4f
                from main import selected_provider
                response = g4f.ChatCompletion.create(
                    model=g4f.models.default,
                    messages=[
                        {"role": "system", "content": "You are Resonant, an OSINT AI assistant. Help with investigations."},
                        {"role": "user", "content": user_message}
                    ],
                    provider=selected_provider,
                    timeout=30
                )
                if response:
                    return response
            except Exception as api_error:
                app.logger.warning(f"Direct API also failed: {api_error}")

            # Final fallback response
            return f"I'm Resonant OSINT AI. I would help investigate: '{user_message}'\n\nNote: AI backend is experiencing issues. For now, I can't use my tools but I'm here to guide your investigation."

        except Exception as e:
            app.logger.error(f"Error in get_ai_response: {e}")
            # Very basic fallback
            return f"Resonant OSINT Assistant\n\nQuery: {user_message}\n\nI'm currently experiencing technical difficulties. Please try:\n1. Check your internet connection\n2. Try a simpler query\n3. Wait a few minutes and try again"

    @app.route('/chat/<chat_id>/message', methods=['POST'])
    @login_required
    def send_message(chat_id):
        try:
            chat = db.session.query(Chat).with_for_update().filter_by(
                id=chat_id, user_id=current_user.id
            ).first()
            if not chat:
                return jsonify({'error': 'Chat not found'}), 404

            content = (request.get_json(silent=True) or {}).get('message') or ''
            if not content:
                return jsonify({'error': 'Message is required'}), 400
            if len(content) > 4000:
                return jsonify({'error': 'Message is too long (max 4000 characters)'}), 400

            # Each message can trigger many outbound lookups and uses a shared
            # free-provider quota, so cap how fast one account can send them.
            msg_key = f'msg:{current_user.id}'
            if limiter.blocked(msg_key, AI_MESSAGES_PER_HOUR, 3600):
                return jsonify({'error': f'Rate limit reached ({AI_MESSAGES_PER_HOUR} messages per hour). Please try again later.'}), 429
            limiter.hit(msg_key, 3600)

            # Save user message
            user_msg = Message(chat_id=chat_id, content=content, is_user=True)
            db.session.add(user_msg)
            db.session.commit()

            # Retrieve full chat history
            messages = Message.query.filter_by(
                chat_id=chat_id
            ).order_by(Message.timestamp).all()

            # Get AI response
            ai_content = get_ai_response(content, messages)

            # Save AI response
            ai_msg = Message(chat_id=chat_id, content=ai_content, is_user=False)
            db.session.add(ai_msg)
            db.session.commit()

            return jsonify({
                'response': ai_content,
                'user_message_id': user_msg.id,
                'ai_message_id': ai_msg.id
            })

        except Exception as e:
            app.logger.error(f'Error in send_message: {e}', exc_info=True)
            db.session.rollback()
            
            # User-friendly error message
            error_message = f"**System Error**\n\n"
            error_message += f"Sorry, I encountered an error processing your message.\n\n"
            error_message += f"**What to try:**\n"
            error_message += f"• Check your internet connection\n"
            error_message += f"• Try a simpler query\n"
            error_message += f"• Wait a moment and try again\n\n"
            error_message += f"**Technical details:** {str(e)[:150]}"
            
            return jsonify({
                'error': error_message
            }), 500

    @app.route('/chat/<chat_id>/clear_chat', methods=['POST'])
    @login_required
    def clear_chat(chat_id):
        try:
            chat = db.session.query(Chat).with_for_update().filter_by(
                id=chat_id, user_id=current_user.id
            ).first()
            if not chat:
                return jsonify({'error': 'Chat not found or unauthorized'}), 404

            # Delete all messages and then the chat
            Message.query.filter_by(chat_id=chat.id).delete()
            db.session.delete(chat)
            db.session.commit()

            return jsonify({
                'status': 'success',
                'message': 'Chat cleared successfully'
            })

        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f'Database error clearing chat: {e}')
            return jsonify({'error': 'Database error during chat clearing'}), 500

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Unexpected error clearing chat: {e}')
            return jsonify({'error': 'Unexpected error clearing chat'}), 500

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'same-origin')
        return response

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db.session.remove()

    return app


if __name__ == '__main__':
    app = create_app(os.getenv('FLASK_ENV', 'default'))
    # Debug mode exposes an interactive debugger, so it is opt-in only, and the
    # server binds to localhost unless you explicitly set HOST.
    debug = os.getenv('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes')
    app.run(
        host=os.getenv('HOST', '127.0.0.1'),
        port=int(os.getenv('PORT', '5000')),
        debug=debug,
        threaded=True,
    )
