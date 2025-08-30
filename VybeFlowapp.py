from flask import Flask
app = Flask(__name__)

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)

# --- Advanced Livestream Features ---
# Live Reaction (emoji, heart, etc.)
class LiveReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(16), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Live Poll

# --- Gangsta/Wild N Out Features ---
# Battle Room model
class BattleRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

# Crew model
class Crew(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    banner = db.Column(db.String(255), nullable=True)
    avatar = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Live Q&A
class LiveQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question = db.Column(db.String(255), nullable=False)
    is_highlighted = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Virtual Gift
class VirtualGift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    gift_type = db.Column(db.String(32), nullable=False)  # e.g., 'coin', 'sticker', 'rose'
    amount = db.Column(db.Integer, default=1)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Achievement/Badge
class Achievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(255))
    earned_at = db.Column(db.DateTime, default=datetime.utcnow)

# Co-Stream (multi-user live)
class CoStream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_ids = db.Column(db.Text, nullable=False)  # JSON list of user ids
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime, nullable=True)

# Overlay (theme, AR, etc.)
class StreamOverlay(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    overlay_type = db.Column(db.String(32), nullable=False)  # 'theme', 'ar', etc.
    data = db.Column(db.Text, nullable=True)  # JSON or config

# Music Integration
class StreamMusic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    track_url = db.Column(db.String(255), nullable=False)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# AR Filter
class ARFilter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    file_url = db.Column(db.String(255), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_public = db.Column(db.Boolean, default=True)

# VIP/Private Stream
class VIPStreamAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    purchased_at = db.Column(db.DateTime, default=datetime.utcnow)

# Highlight
class StreamHighlight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    start_time = db.Column(db.Float, nullable=False)
    end_time = db.Column(db.Float, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Live Map (Discovery)
class LiveLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    city = db.Column(db.String(64), nullable=True)
    country = db.Column(db.String(64), nullable=True)

# --- End Advanced Livestream Features ---
# --- Livestream Feature Routes (stubs) ---
@app.route('/live/<int:post_id>/reactions', methods=['POST'])
def live_reaction(post_id):
    # Add a reaction to a live stream
    emoji = request.form.get('emoji')
    if 'user_id' in session and emoji:
        reaction = LiveReaction(post_id=post_id, user_id=session['user_id'], emoji=emoji)
        db.session.add(reaction)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 400

@app.route('/live/<int:post_id>/poll', methods=['POST'])
def live_poll(post_id):
    # Create a poll for a live stream
    question = request.form.get('question')
    options = request.form.get('options')  # JSON list
    if 'user_id' in session and question and options:
        poll = LivePoll(post_id=post_id, question=question, options=options)
        db.session.add(poll)
        db.session.commit()
        return jsonify({'status': 'ok', 'poll_id': poll.id})
    return jsonify({'status': 'error'}), 400

@app.route('/live/poll/<int:poll_id>/vote', methods=['POST'])
def live_poll_vote(poll_id):
    # Vote in a live poll
    option = request.form.get('option')
    if 'user_id' in session and option:
        vote = LivePollVote(poll_id=poll_id, user_id=session['user_id'], option=option)
        db.session.add(vote)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 400

@app.route('/live/<int:post_id>/question', methods=['POST'])
def live_question(post_id):
    # Submit a question for Q&A
    question = request.form.get('question')
    if 'user_id' in session and question:
        q = LiveQuestion(post_id=post_id, user_id=session['user_id'], question=question)
        db.session.add(q)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 400

@app.route('/live/<int:post_id>/gift', methods=['POST'])
def live_gift(post_id):
    # Send a virtual gift
    gift_type = request.form.get('gift_type')
    amount = int(request.form.get('amount', 1))
    if 'user_id' in session and gift_type:
        gift = VirtualGift(post_id=post_id, user_id=session['user_id'], gift_type=gift_type, amount=amount)
        db.session.add(gift)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 400

@app.route('/live/<int:post_id>/highlight', methods=['POST'])
def live_highlight(post_id):
    # Create a highlight for a stream
    start = float(request.form.get('start'))
    end = float(request.form.get('end'))
    if 'user_id' in session:
        highlight = StreamHighlight(post_id=post_id, start_time=start, end_time=end, created_by=session['user_id'])
        db.session.add(highlight)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 400

@app.route('/live/<int:post_id>/music', methods=['POST'])
def live_music(post_id):
    # Add a music track to the stream
    track_url = request.form.get('track_url')
    if 'user_id' in session and track_url:
        music = StreamMusic(post_id=post_id, track_url=track_url, added_by=session['user_id'])
        db.session.add(music)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 400

@app.route('/live/<int:post_id>/overlay', methods=['POST'])
def live_overlay(post_id):
    # Add or update overlay
    overlay_type = request.form.get('overlay_type')
    data = request.form.get('data')
    if 'user_id' in session and overlay_type:
        overlay = StreamOverlay(post_id=post_id, overlay_type=overlay_type, data=data)
        db.session.add(overlay)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 400

@app.route('/live/<int:post_id>/arfilter', methods=['POST'])
def live_arfilter(post_id):
    # Add AR filter to stream
    filter_id = request.form.get('filter_id')
    if 'user_id' in session and filter_id:
        # Just a stub, would link ARFilter to stream
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 400

@app.route('/live/<int:post_id>/vip', methods=['POST'])
def live_vip(post_id):
    # Grant VIP access
    if 'user_id' in session:
        access = VIPStreamAccess(post_id=post_id, user_id=session['user_id'])
        db.session.add(access)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 400

@app.route('/live/<int:post_id>/location', methods=['POST'])
def live_location(post_id):
    # Set live location for discovery
    lat = float(request.form.get('lat'))
    lng = float(request.form.get('lng'))
    city = request.form.get('city')
    country = request.form.get('country')
    if 'user_id' in session:
        loc = LiveLocation(post_id=post_id, lat=lat, lng=lng, city=city, country=country)
        db.session.add(loc)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 400
# --- End Livestream Feature Routes ---
import os
import io
import re
import json
import base64
import random
import requests

from datetime import datetime, timedelta
import random
import os
# --- Gangsta/Wild N Out Features ---
# Battle Room model
class BattleRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

# Crew model
class Crew(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    banner = db.Column(db.String(255), nullable=True)
    avatar = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Crew Membership
class CrewMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

# Battle (Rap Battle, Roast, Freestyle)
class Battle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('battle_room.id'), nullable=False)
    challenger_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    opponent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    winner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    battle_type = db.Column(db.String(32), default='freestyle')  # 'freestyle', 'roast', 'wildstyle'
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)

# Battle Vote
class BattleVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    battle_id = db.Column(db.Integer, db.ForeignKey('battle.id'), nullable=False)
    voter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    voted_for_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    voted_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- End Gangsta/Wild N Out Features ---
# Gangsta Profile Badge
def get_gangsta_badge(user):
    # Example: assign badge based on battles won
    battles_won = Battle.query.filter_by(winner_id=user.id).count()
    if battles_won >= 20:
        return 'OG Legend'
    elif battles_won >= 10:
        return 'Wildstyle Champ'
    elif battles_won >= 3:
        return 'Battle Star'
    return None
# --- Gangsta/Wild N Out Routes ---
@app.route('/battlerooms')
def battlerooms():
    rooms = BattleRoom.query.filter_by(is_active=True).all()
    return render_template('battlerooms.html', rooms=rooms)

@app.route('/battleroom/<int:room_id>')
def battleroom(room_id):
    room = BattleRoom.query.get_or_404(room_id)
    battles = Battle.query.filter_by(room_id=room.id).order_by(Battle.started_at.desc()).all()
    return render_template('battleroom.html', room=room, battles=battles)

@app.route('/battle/<int:battle_id>', methods=['GET', 'POST'])
def battle(battle_id):
    battle = Battle.query.get_or_404(battle_id)
    challenger = User.query.get(battle.challenger_id)
    opponent = User.query.get(battle.opponent_id)
    votes_challenger = BattleVote.query.filter_by(battle_id=battle.id, voted_for_id=challenger.id).count()
    votes_opponent = BattleVote.query.filter_by(battle_id=battle.id, voted_for_id=opponent.id).count()
    if request.method == 'POST' and 'user_id' in session:
        voted_for = int(request.form['voted_for'])
        if not BattleVote.query.filter_by(battle_id=battle.id, voter_id=session['user_id']).first():
            vote = BattleVote(battle_id=battle.id, voter_id=session['user_id'], voted_for_id=voted_for)
            db.session.add(vote)
            db.session.commit()
            flash('Vote submitted!')
        return redirect(url_for('battle', battle_id=battle.id))
    return render_template('battle.html', battle=battle, challenger=challenger, opponent=opponent, votes_challenger=votes_challenger, votes_opponent=votes_opponent)

@app.route('/crews')
def crews():
    crews = Crew.query.all()
    return render_template('crews.html', crews=crews)

@app.route('/crew/<int:crew_id>')
def crew(crew_id):
    crew = Crew.query.get_or_404(crew_id)
    members = CrewMember.query.filter_by(crew_id=crew.id).all()
    return render_template('crew.html', crew=crew, members=members)

@app.route('/leaderboard')
def leaderboard():
    # Top battlers and crews
    top_battlers = db.session.query(User, db.func.count(Battle.id).label('wins')).join(Battle, Battle.winner_id == User.id).group_by(User.id).order_by(db.desc('wins')).limit(10).all()
    top_crews = db.session.query(Crew, db.func.count(CrewMember.id).label('members')).join(CrewMember, CrewMember.crew_id == Crew.id).group_by(Crew.id).order_by(db.desc('members')).limit(10).all()
    return render_template('leaderboard.html', top_battlers=top_battlers, top_crews=top_crews)

# --- End Gangsta/Wild N Out Routes ---
from threading import Thread
from flask import Flask, render_template, redirect, request, session, url_for, abort, flash, jsonify, Blueprint, current_app
from flask_cors import CORS
from functools import wraps
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.contrib.google import make_google_blueprint, google
from flask_socketio import SocketIO, emit, join_room, leave_room
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
from flask_wtf import FlaskForm
import time
try:
    from pywebpush import webpush, WebPushException
except ImportError:
    webpush = None
    WebPushException = Exception
try:
    import spacy
except ImportError:
    spacy = None
try:
    from authlib.integrations.flask_client import OAuth
except ImportError:
    OAuth = None
import numpy as np
import soundfile as sf

# Ensure login_required is defined before any use
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Form classes - defined at module level before app initialization
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')



# --- Privacy Policy and Terms of Service Routes ---
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# --- Account Deletion (GDPR/CCPA) ---
@app.route('/account/delete', methods=['GET', 'POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        # Delete user and all related data
        # (You may want to anonymize instead of hard delete in production)
        db.session.delete(user)
        db.session.commit()
        session.pop('user_id', None)
        flash('Your account and data have been deleted.')
        return redirect(url_for('homepage'))
    return render_template('delete_account.html', user=user)

# --- Global Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# --- Flask App Config: Security Hardening ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('VYBEFLOW_SECRET_KEY', os.urandom(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('VYBEFLOW_DB_URI', 'sqlite:///vybeflow.db')
app.config['UPLOAD_FOLDER'] = os.environ.get('VYBEFLOW_UPLOAD_FOLDER', 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size
# Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'vybeflow@gmail.com')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'vybeflow@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'yourpassword')
# Twilio configuration
app.config['TWILIO_ACCOUNT_SID'] = os.environ.get('TWILIO_ACCOUNT_SID', 'your_account_sid')
app.config['TWILIO_AUTH_TOKEN'] = os.environ.get('TWILIO_AUTH_TOKEN', 'your_auth_token')
app.config['TWILIO_PHONE_NUMBER'] = os.environ.get('TWILIO_PHONE_NUMBER', '+1234567890')
# Secure session cookies
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
# Force HTTPS (behind proxy/load balancer)
app.config['PREFERRED_URL_SCHEME'] = 'https'

# --- CSRF Protection ---
csrf = CSRFProtect(app)

# --- HTTP Security Headers ---
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://accounts.google.com https://upload.wikimedia.org; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://upload.wikimedia.org;"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

db = SQLAlchemy(app)
limiter = Limiter(app)
csrf = CSRFProtect(app)

facebook_bp = make_facebook_blueprint(
    client_id="YOUR_FACEBOOK_APP_ID",
    client_secret="YOUR_FACEBOOK_APP_SECRET",
    redirect_to="feed"
)
app.register_blueprint(facebook_bp, url_prefix="/facebook_login")

google_bp = make_google_blueprint(
    client_id="YOUR_GOOGLE_CLIENT_ID",
    client_secret="YOUR_GOOGLE_CLIENT_SECRET",
    scope=["profile", "email"],
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/google_login")

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
# socketio = SocketIO(app)  # Temporarily disabled
# --- Secure config from environment variables ---

# Missing function definitions
def async_review_story(story_id):
    """Async function to review story content"""
    pass

# Missing VAPID key (for push notifications)
VAPID_PRIVATE_KEY = "your-vapid-private-key-here"

from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
tiktok = oauth.register(
    name='tiktok',
    client_id='YOUR_TIKTOK_CLIENT_KEY',
    client_secret='YOUR_TIKTOK_CLIENT_SECRET',
    access_token_url='https://open-api.tiktok.com/oauth/access_token/',
    authorize_url='https://open-api.tiktok.com/platform/oauth/connect/',
    api_base_url='https://open-api.tiktok.com/',
    client_kwargs={'scope': 'user.info.basic'}
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    bio = db.Column(db.String(255))
    avatar = db.Column(db.String(120), default='default_avatar.png')
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_private = db.Column(db.Boolean, default=False)  # New field for private accounts
    cover_photo = db.Column(db.String(120), default='default_cover.jpg')  # Add to User model
    email_notifications = db.Column(db.Boolean, default=True)  # Add to User model
    phone = db.Column(db.String(20), unique=True, nullable=True)
    phone_verified = db.Column(db.Boolean, default=False)
    failed_logins = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    theme = db.Column(db.String(50), default='light')  # e.g., 'rap', 'gospel', etc.
    custom_background = db.Column(db.String(255), nullable=True)  # Path or URL to custom background
    is_under_review = db.Column(db.Boolean, default=False)
    review_requested_at = db.Column(db.DateTime, nullable=True)
    push_subscription = db.Column(db.Text, nullable=True)  # For storing push notification subscriptions
    facebook_handle = db.Column(db.String(120), nullable=True)
    instagram_handle = db.Column(db.String(120), nullable=True)
    instagram_access_token = db.Column(db.String(255), nullable=True)
    instagram_user_id = db.Column(db.String(120), nullable=True)
    tiktok_handle = db.Column(db.String(120), nullable=True)
    snapchat_handle = db.Column(db.String(120), nullable=True)
    custom_theme_video = db.Column(db.String(120), nullable=True)  # New field for custom theme video

    # Profile Anthem (VybeCheck)
    profile_anthem_url = db.Column(db.String(255), nullable=True)  # URL to music track
    profile_anthem_genre = db.Column(db.String(50), nullable=True, default='hip_hop')

    # Custom Layouts (JSON config for profile blocks)
    custom_layout = db.Column(db.Text, nullable=True)  # JSON string for layout config

# Post model (moved from stray fields)
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    media_filename = db.Column(db.String(120))
    media_type = db.Column(db.String(10), nullable=False)  # 'image', 'video', or 'live'
    caption = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    live_url = db.Column(db.String(255))  # New field for live stream URLs
    is_reported = db.Column(db.Boolean, default=False)  # New field to track reported posts
    is_private = db.Column(db.Boolean, default=False)  # New field for private posts
    # Define relationship with User
    user = db.relationship('User', backref=db.backref('posts', lazy=True))

    # Content warning tags
    content_tag = db.Column(db.String(32), nullable=True)  # 'artistic', 'educational', 'unfiltered', or None

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)  # For replies
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')

class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

class Compliment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Ban(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)  # None means permanent
    reason = db.Column(db.String(255), nullable=True)  # Add this line

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.String(1000))
    voice_filename = db.Column(db.String(120))  # For voice notes
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    self_destruct = db.Column(db.Boolean, default=False)  # Unique feature
    scheduled_at = db.Column(db.DateTime, nullable=True)  # Add to Message model

class MessageReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)

class CommentReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(50), nullable=True)  # e.g., "😂", "🤣", or a 3D emoji name
    gif_url = db.Column(db.String(255), nullable=True)  # URL to a GIF if used

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    media_filename = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_banned = db.Column(db.Boolean, default=False)
    warning_count = db.Column(db.Integer, default=0)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    theme = db.Column(db.String(50), default='light')  # Add this line
    is_art_nudity = db.Column(db.Boolean, default=False)  # True for Art & Nudity groups
    age_restricted = db.Column(db.Boolean, default=False)  # Age restriction flag
    custom_rules = db.Column(db.Text, nullable=True)  # Community moderation rules
# Private Collection model
class PrivateCollection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(255))
    password_hash = db.Column(db.String(128), nullable=True)  # If set, collection is password-protected
    is_nudity = db.Column(db.Boolean, default=False)  # True if for nudity/art
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Relationship: user = db.relationship('User', backref=db.backref('private_collections', lazy=True))

# Private Collection Item model
class PrivateCollectionItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    collection_id = db.Column(db.Integer, db.ForeignKey('private_collection.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    caption = db.Column(db.String(255), nullable=True)
    is_nudity = db.Column(db.Boolean, default=False)
# Route to create an Art & Nudity group
@app.route('/groups/create_art_nudity', methods=['GET', 'POST'])
def create_art_nudity_group():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        custom_rules = request.form.get('custom_rules', '')
        group = Group(
            name=name,
            description=description,
            theme='art_nudity',
            is_art_nudity=True,
            age_restricted=True,
            custom_rules=custom_rules
        )
        db.session.add(group)
        db.session.commit()
        flash('Art & Nudity group created!')
        return redirect(url_for('group', group_id=group.id))
    return render_template('create_art_nudity_group.html')

# Route to create a private collection
@app.route('/collections/create', methods=['GET', 'POST'])
def create_private_collection():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        password = request.form.get('password')
        is_nudity = bool(request.form.get('is_nudity'))
        password_hash = generate_password_hash(password) if password else None
        collection = PrivateCollection(
            user_id=session['user_id'],
            name=name,
            description=description,
            password_hash=password_hash,
            is_nudity=is_nudity
        )
        db.session.add(collection)
        db.session.commit()
        flash('Private collection created!')
        return redirect(url_for('view_private_collection', collection_id=collection.id))
    return render_template('create_private_collection.html')

# Route to view a private collection (with password check if needed)
@app.route('/collections/<int:collection_id>', methods=['GET', 'POST'])
def view_private_collection(collection_id):
    collection = PrivateCollection.query.get_or_404(collection_id)
    # Check permission: owner or password
    if collection.password_hash:
        if 'collection_access' not in session or session['collection_access'] != collection_id:
            if request.method == 'POST':
                password = request.form.get('password')
                if password and check_password_hash(collection.password_hash, password):
                    session['collection_access'] = collection_id
                else:
                    flash('Incorrect password.')
                    return render_template('private_collection_password.html', collection=collection)
            else:
                return render_template('private_collection_password.html', collection=collection)
    items = PrivateCollectionItem.query.filter_by(collection_id=collection.id).all()
    return render_template('private_collection.html', collection=collection, items=items)

# Route to upload to a private collection
@app.route('/collections/<int:collection_id>/upload', methods=['POST'])
def upload_to_private_collection(collection_id):
    collection = PrivateCollection.query.get_or_404(collection_id)
    if collection.user_id != session.get('user_id'):
        abort(403)
    file = request.files['file']
    caption = request.form.get('caption')
    is_nudity = bool(request.form.get('is_nudity'))
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    item = PrivateCollectionItem(
        collection_id=collection.id,
        filename=filename,
        caption=caption,
        is_nudity=is_nudity
    )
    db.session.add(item)
    db.session.commit()
    flash('File uploaded to collection!')
    return redirect(url_for('view_private_collection', collection_id=collection.id))

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device_info = db.Column(db.String(255))
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    session_token = db.Column(db.String(128))

class StoryView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class StoryReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)

class SavedStory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    saved_at = db.Column(db.DateTime, default=datetime.utcnow)

class GroupConfession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    text = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class GroupChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.String(1000))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('group_chat_message.id'), nullable=True)  # For threaded replies
    is_announcement = db.Column(db.Boolean, default=False)  # For admin announcements
    is_pinned = db.Column(db.Boolean, default=False)        # For pinning messages

HATE_WORDS = {'hateword1', 'hateword2', 'hateword3'}  # Add real hate words here

def contains_hate(text):
    return any(word in text.lower() for word in HATE_WORDS)

def check_story_for_hate(story):
    if contains_hate(story.media_filename) or contains_hate(story.caption if hasattr(story, 'caption') else ''):
        story.warning_count += 1
        if story.warning_count == 3:
            notify(story.user_id, "Warning 3/3: If you do this crap again your account is banned.")
        if story.warning_count > 3:
            story.is_banned = True
            notify(story.user_id, "Your story was banned for repeated hate speech.")
        else:
            notify(story.user_id, f"Warning {story.warning_count}/3: Hate speech detected in your story.")
        db.session.commit()

def notify(user_id, message):
    n = Notification(user_id=user_id, message=message)
    db.session.add(n)
    db.session.commit()

def is_username_allowed(username):
    # Only block hate/illegal words, not general slang or cursing
    return not contains_hate(username)


@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        form = RegistrationForm()
    except NameError as e:
        flash(f'Form initialization error: {e}. Please refresh the page.')
        # Create a dummy form to prevent template errors
        class DummyForm:
            def validate_on_submit(self):
                return False
            def __init__(self):
                self.username = type('obj', (object,), {'data': ''})()
                self.email = type('obj', (object,), {'data': ''})()
                self.password = type('obj', (object,), {'data': ''})()
                self.password2 = type('obj', (object,), {'data': ''})()
        form = DummyForm()
        return render_template('register.html', form=form, show_instagram_signup=True)
    
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        if not is_username_allowed(username):
            flash('Username contains prohibited words.')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('register'))
        password_hash = generate_password_hash(password)
        user = User(username=username, password_hash=password_hash, email=email)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, show_instagram_signup=True)

# Instagram OAuth sign-up initiation route
@app.route('/instagram_signup')
def instagram_signup():
    # This should redirect to the Instagram OAuth flow
    # Placeholder: flash and redirect for now
    flash('Instagram sign up coming soon!')
    return redirect(url_for('register'))

@app.route('/register_phone', methods=['GET', 'POST'])
def register_phone():
    """Phone registration route"""
    if request.method == 'POST':
        username = request.form.get('username')
        phone = request.form.get('phone')
        password = request.form.get('password')
        
        if not username or not phone or not password:
            flash('All fields are required.')
            return redirect(url_for('register_phone'))
            
        if not is_username_allowed(username):
            flash('Username contains prohibited words.')
            return redirect(url_for('register_phone'))
            
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register_phone'))
            
        if User.query.filter_by(phone=phone).first():
            flash('Phone number already registered.')
            return redirect(url_for('register_phone'))
            
        password_hash = generate_password_hash(password)
        user = User(
            username=username, 
            password_hash=password_hash, 
            phone=phone,
            email=f"{username}@vybeflow.temp"  # Temporary email for phone-only registration
        )
        db.session.add(user)
        db.session.commit()
        flash('Phone registration successful. Please log in.')
        return redirect(url_for('login'))
        
    return render_template('register_phone.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    try:
        form = LoginForm()
    except NameError as e:
        flash(f'Form initialization error: {e}. Please refresh the page.')
        # Create a dummy form to prevent template errors
        class DummyForm:
            def validate_on_submit(self):
                return False
            def __init__(self):
                self.username = type('obj', (object,), {'data': ''})()
                self.password = type('obj', (object,), {'data': ''})()
        form = DummyForm()
        return render_template('login.html', form=form)
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session.permanent = True
            return redirect(url_for('feed'))
        if user and user.lockout_until and user.lockout_until > datetime.utcnow():
            flash('Account locked. Try again later.')
            return render_template('login.html', form=form)
        if user and not check_password_hash(user.password_hash, password):
            user.failed_logins += 1
            if user.failed_logins >= 5:
                user.lockout_until = datetime.utcnow() + timedelta(minutes=15)
                flash('Account locked for 15 minutes due to too many failed attempts.')
            db.session.commit()
            flash('Invalid credentials.')
            return render_template('login.html', form=form)
        if user:
            user.failed_logins = 0
            user.lockout_until = None
            db.session.commit()
        flash('Invalid credentials.')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))

def get_backgrounds_for_user(user):
    # Example: Map user.theme or interests to background files
    theme_backgrounds = {
        'nature': ['nature1.jpg', 'nature2.mp4'],
        'art': ['art1.jpg', 'art2.mp4'],
        'sports': ['sports1.jpg', 'sports2.mp4'],
        'gospel': ['gospel1.jpg', 'gospel2.mp4'],
        'rap': ['rap1.jpg', 'rap2.mp4'],
        'hip_hop': ['hiphop1.jpg', 'hiphop2.mp4'],
        'gangsta': ['gangsta1.jpg', 'gangsta2.mp4'],
        # Add more themes and files as needed
        'default': ['default1.jpg', 'default2.mp4']
    }
    theme = getattr(user, 'theme', 'default')
    return theme_backgrounds.get(theme, theme_backgrounds['default'])

@app.route('/')
def homepage():
    """Landing page for new visitors"""
    if 'user_id' in session:
        return redirect(url_for('feed'))
    return render_template('homepage.html')

@app.route('/feed')
@login_required
def feed():
    """Main social feed with posts from followed users"""
    user = User.query.get(session['user_id'])
    
    # Get posts from followed users and own posts
    followed_users = db.session.query(Follow.followed_id).filter_by(follower_id=user.id).subquery()
    posts = Post.query.join(User).filter(
        (Post.user_id.in_(followed_users)) | (Post.user_id == user.id)
    ).order_by(Post.timestamp.desc()).limit(50).all()
    
    # If no posts from followed users, show recent public posts
    if not posts:
        posts = Post.query.join(User).order_by(Post.timestamp.desc()).limit(20).all()
    
    # Get suggested users to follow
    suggested_users = User.query.filter(
        User.id != user.id,
        ~User.id.in_(db.session.query(Follow.followed_id).filter_by(follower_id=user.id))
    ).limit(5).all()
    
    backgrounds = get_backgrounds_for_user(user)
    trending_users = get_trending_users()
    return render_template('feed.html', posts=posts, backgrounds=backgrounds, trending_users=trending_users, 
                         suggested_users=suggested_users, current_user=user)

@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    """Follow a user"""
    current_user_id = session['user_id']
    
    # Check if already following
    existing_follow = Follow.query.filter_by(
        follower_id=current_user_id, 
        followed_id=user_id
    ).first()
    
    if not existing_follow and current_user_id != user_id:
        follow = Follow(follower_id=current_user_id, followed_id=user_id)
        db.session.add(follow)
        db.session.commit()
        flash('User followed successfully!')
    
    return redirect(request.referrer or url_for('feed'))

@app.route('/unfollow/<int:user_id>', methods=['POST'])
@login_required
def unfollow_user(user_id):
    """Unfollow a user"""
    current_user_id = session['user_id']
    
    follow = Follow.query.filter_by(
        follower_id=current_user_id, 
        followed_id=user_id
    ).first()
    
    if follow:
        db.session.delete(follow)
        db.session.commit()
        flash('User unfollowed successfully!')
    
    return redirect(request.referrer or url_for('feed'))

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'glb', 'gltf', 'obj'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        if not request.form.get('not_graphic'):
            flash('You must confirm your photo is not graphic or violent.')
            return redirect(request.url)
        if 'image' not in request.files:
            flash('No file part.')
            return redirect(request.url)
        file = request.files['image']
        if file.filename == '':
            flash('No selected file.')
            return redirect(request.url)
        if not allowed_file(file.filename):
            flash('File type not allowed.')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower()
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        caption = request.form.get('caption', '')
        if file_ext in ['glb', 'gltf', 'obj']:
            media_type = '3d'
        elif file_ext in ['mp4']:
            media_type = 'video'
        else:
            media_type = 'image'
    # Content tag
    content_tag = request.form.get('content_tag')  # 'artistic', 'educational', 'unfiltered', or None
    post = Post(media_filename=filename, media_type=media_type, caption=caption, user_id=session['user_id'], content_tag=content_tag)
    db.session.add(post)
    db.session.commit()
    flash('Post uploaded successfully.')
    return redirect(url_for('feed'))
    return render_template('upload.html')

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.id.desc()).all()
    anthem_url = user.profile_anthem_url
    anthem_genre = user.profile_anthem_genre or 'hip_hop'
    custom_bg = user.custom_background
    custom_layout = user.custom_layout
    # If visitor is a hip hop lover, blast anthem
    visitor_theme = session.get('theme', None)
    blast_anthem = anthem_url if anthem_url and (visitor_theme == 'hip_hop' or anthem_genre == 'hip_hop') else None
    return render_template(
        'profile.html',
        user=user,
        posts=posts,
        anthem_url=anthem_url,
        blast_anthem=blast_anthem,
        custom_bg=custom_bg,
        custom_layout=custom_layout
    )

@app.route('/profile/customize', methods=['GET', 'POST'])
def customize_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    themes = [
        'light', 'dark', 'cyberpunk', 'retro_neon', 'nature', 'minimalist_dark',
        'gospel', 'rap', 'hip_hop', 'rnb', 'fun', 'pastel', 'vaporwave', 'beach', 'forest'
    ]
    if request.method == 'POST':
        user.theme = request.form.get('theme', user.theme)
        # Profile anthem
        user.profile_anthem_url = request.form.get('profile_anthem_url')
        user.profile_anthem_genre = request.form.get('profile_anthem_genre', 'hip_hop')
        # Custom layout (as JSON string)
        layout_json = request.form.get('custom_layout')
        if layout_json:
            user.custom_layout = layout_json
        # Handle custom background upload
        if 'custom_background' in request.files:
            file = request.files['custom_background']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.custom_background = filename
        db.session.commit()
        flash('Profile customized!')
        return redirect(url_for('profile', username=user.username))
    return render_template('customize_profile.html', user=user, themes=themes)

@app.route('/like/<int:post_id>', methods=['POST'])
def like(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    like = Like.query.filter_by(user_id=session['user_id'], post_id=post_id).first()
    if not like:
        db.session.add(Like(user_id=session['user_id'], post_id=post_id))
        db.session.commit()
        flash('Post liked!')
    else:
        flash('You already liked this post!')
    return redirect(request.referrer)

@app.route('/like_post/<int:post_id>', methods=['POST'])
def like_post(post_id):
    """Alternative route name for like functionality"""
    return like(post_id)

@app.route('/comment/<int:post_id>', methods=['POST'])
def comment(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    text = request.form['text']
    parent_id = request.form.get('parent_id')
    comment = Comment(text=text, user_id=session['user_id'], post_id=post_id, parent_id=parent_id)
    db.session.add(comment)
    db.session.commit()
    check_comment_for_harassment(comment)  # <-- Add this line
    return redirect(request.referrer)

# Add a set of harassment/threat keywords (customize as needed)
HARASSMENT_KEYWORDS = {'harass', 'threat', 'kill', 'hurt', 'attack', 'abuse', 'bully'}

def contains_harassment(text):
    return any(word in text.lower() for word in HARASSMENT_KEYWORDS)

def check_comment_for_harassment(comment):
    user = User.query.get(comment.user_id)
    if contains_harassment(comment.text):
        if not hasattr(user, 'harassment_warning_count'):
            user.harassment_warning_count = 0
        user.harassment_warning_count += 1
        db.session.commit()
        if user.harassment_warning_count >= 3:
            # Ban the user after 3 warnings
            ban = Ban.query.filter_by(user_id=user.id).first()
            if not ban:
                ban = Ban(user_id=user.id, expires_at=None, reason="Harassment or threats after 3 warnings.")
                db.session.add(ban)
            else:
                ban.reason = "Harassment or threats after 3 warnings."
                ban.expires_at = None
            db.session.commit()
            notify(user.id, "your outta here!")
        else:
            notify(user.id, f"Warning {user.harassment_warning_count}/3: Harassment or threat detected. After 3 warnings, you will be banned.")
        db.session.commit()

@app.route('/facebook')
def facebook_login():
    if not facebook.authorized:
        return redirect(url_for("facebook.login"))
    resp = facebook.get("/me?fields=id,name")
    facebook_info = resp.json()
    facebook_id = facebook_info["id"]
    user = User.query.filter_by(username=facebook_info["name"]).first()
    if not user:
        user = User(username=facebook_info["name"])
        db.session.add(user)
        db.session.commit()
    session['user_id'] = user.id
    return redirect(url_for("feed"))

@app.route('/google')
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash('Google authentication failed. Please try again.')
        return redirect(url_for('login'))
    
    google_info = resp.json()
    google_id = google_info["id"]
    email = google_info["email"]
    username = google_info.get("name", email.split("@")[0])
    
    # Check if user already exists
    user = User.query.filter_by(email=email).first()
    if not user:
        # Create new user with Google account - no password needed
        # Ensure username is unique
        base_username = username.replace(" ", "").lower()
        counter = 1
        unique_username = base_username
        while User.query.filter_by(username=unique_username).first():
            unique_username = f"{base_username}{counter}"
            counter += 1
        
        # Create user with temporary password (Google OAuth user)
        temp_password_hash = generate_password_hash(f"google_oauth_{google_id}_{random.randint(1000, 9999)}")
        user = User(
            username=unique_username, 
            email=email, 
            password_hash=temp_password_hash,
            is_verified=True,
            bio=f"New VybeFlow member! 🎉"
        )
        db.session.add(user)
        db.session.commit()
        
        flash(f'Welcome to VybeFlow, {user.username}! Your account has been created successfully.')
    else:
        flash(f'Welcome back, {user.username}!')
    
    session['user_id'] = user.id
    session.permanent = True
    return redirect(url_for("feed"))

@app.route('/instagram_callback')
def instagram_callback():
    # Instagram integration placeholder - requires proper OAuth setup
    flash("Instagram linking feature coming soon!")
    return redirect(url_for('account'))

@app.route('/tiktok_login')
def tiktok_login():
    redirect_uri = url_for('tiktok_callback', _external=True)
    return tiktok.authorize_redirect(redirect_uri)

@app.route('/tiktok_callback')
def tiktok_callback():
    token = tiktok.authorize_access_token()
    resp = tiktok.get('oauth/userinfo/', params={'access_token': token['access_token']})
    info = resp.json()
    user = User.query.get(session['user_id'])
    user.tiktok_handle = info['data']['user']['display_name']
    db.session.commit()
    flash("TikTok linked!")
    return redirect(url_for('account'))

@app.route('/golive', methods=['GET', 'POST'])
def golive():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        live_url = request.form['live_url']
        caption = request.form.get('caption', '')
        post = Post(media_type='live', caption=caption, user_id=session['user_id'], live_url=live_url)
        db.session.add(post)
        db.session.commit()
        flash('Your live stream is now shared!')
        return redirect(url_for('live'))
    return render_template('golive.html')

@app.route('/live')
def live():
    live_posts = Post.query.filter_by(media_type='live').order_by(Post.id.desc()).all()
    return render_template('live.html', posts=live_posts)

@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        if 'cover_photo' in request.files:
            file = request.files['cover_photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.cover_photo = filename
        # Add logic for other profile fields here
        db.session.commit()
        flash('Profile updated.')
        return redirect(url_for('account'))
    return render_template('account.html', user=user)

@app.route('/search')
@login_required
def search():
    """Search for users and content"""
    query = request.args.get('q', '')
    if not query:
        return render_template('search.html', users=[], posts=[], query='')
    
    # Search users
    users = User.query.filter(
        User.username.contains(query) | 
        User.bio.contains(query)
    ).limit(20).all()
    
    # Search posts
    posts = Post.query.filter(
        Post.caption.contains(query)
    ).limit(20).all()
    
    return render_template('search.html', users=users, posts=posts, query=query)

@app.route('/messages')
@login_required
def messages():
    """Direct messages inbox"""
    user = User.query.get(session['user_id'])
    # Get conversations where user is involved
    conversations = db.session.query(Message).filter(
        (Message.sender_id == user.id) | (Message.recipient_id == user.id)
    ).order_by(Message.timestamp.desc()).all()
    
    # Group by conversation partner
    grouped_conversations = {}
    for msg in conversations:
        partner_id = msg.recipient_id if msg.sender_id == user.id else msg.sender_id
        if partner_id not in grouped_conversations:
            partner = User.query.get(partner_id)
            grouped_conversations[partner_id] = {
                'partner': partner,
                'last_message': msg,
                'unread_count': 0
            }
    
    return render_template('messages.html', conversations=grouped_conversations.values())

@app.route('/messages/<int:user_id>')
@login_required
def chat(user_id):
    """Chat with specific user"""
    current_user = User.query.get(session['user_id'])
    chat_partner = User.query.get_or_404(user_id)
    
    # Get conversation history
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    return render_template('chat.html', messages=messages, partner=chat_partner)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    """Send a direct message"""
    content = request.form.get('content')
    recipient_id = request.form.get('recipient_id')
    
    if content and recipient_id:
        message = Message(
            sender_id=session['user_id'],
            recipient_id=recipient_id,
            text=content,
            timestamp=datetime.utcnow()
        )
        db.session.add(message)
        db.session.commit()
        
        # Real-time update via SocketIO (temporarily disabled)
        # socketio.emit('new_message', {
        #     'sender_id': session['user_id'],
        #     'content': content,
        #     'timestamp': message.timestamp.isoformat()
        # }, room=f'user_{recipient_id}')
    
    return redirect(url_for('chat', user_id=recipient_id))

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Admin access required.')
        return redirect(url_for('feed'))
    users = User.query.all()
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('admin.html', users=users, posts=posts)

@app.route('/admin/analytics')
def admin_analytics():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        abort(403)
    total_users = User.query.count()
    total_posts = Post.query.count()
    total_comments = Comment.query.count()
    total_likes = Like.query.count()
    active_today = User.query.filter(User.id.in_(
        db.session.query(Post.user_id).filter(Post.id > 0)
    )).count()
    return render_template('admin_analytics.html', total_users=total_users,
                           total_posts=total_posts, total_comments=total_comments,
                           total_likes=total_likes, active_today=active_today)

@app.route('/block/<username>/<duration>')
def block_user(username, duration):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_to_block = User.query.filter_by(username=username).first_or_404()
    if user_to_block.id == session['user_id']:
        flash("You can't block yourself.")
        return redirect(url_for('profile', username=username))
    durations = {'day': 1, 'week': 7, 'month': 30}
    days = durations.get(duration, 1)
    expires_at = datetime.utcnow() + timedelta(days=days)
    block = Block.query.filter_by(blocker_id=session['user_id'], blocked_id=user_to_block.id).first()
    if block:
        block.expires_at = expires_at
    else:
        block = Block(blocker_id=session['user_id'], blocked_id=user_to_block.id, expires_at=expires_at)
        db.session.add(block)
    db.session.commit()
    notify(user_to_block.id, "you got blocked bitch")
    flash(f'User blocked for {duration}.')
    return redirect(url_for('profile', username=username))

@app.route('/unblock/<username>')
def unblock_user(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_to_unblock = User.query.filter_by(username=username).first_or_404()
    block = Block.query.filter_by(blocker_id=session['user_id'], blocked_id=user_to_unblock.id).first()
    if block:
        db.session.delete(block)
        db.session.commit()
        flash('User unblocked.')
    return redirect(url_for('profile', username=username))

@app.route('/compliment/<username>', methods=['GET', 'POST'])
def compliment(username):
    recipient = User.query.filter_by(username=username).first_or_404()
    if request.method == 'POST':
        message = request.form['message']
        compliment = Compliment(recipient_id=recipient.id, message=message)
        db.session.add(compliment)
        db.session.commit()
        flash('Your anonymous compliment was sent!')
        return redirect(url_for('profile', username=username))
    return render_template('compliment.html', recipient=recipient)

@app.route('/my_compliments')
def my_compliments():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    compliments = Compliment.query.filter_by(recipient_id=session['user_id']).order_by(Compliment.timestamp.desc()).all()
    return render_template('my_compliments.html', compliments=compliments)

# Serializer for generating tokens
def get_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])

def send_verification_email(user):
    token = s.dumps(user.email, salt='email-confirm')
    link = url_for('confirm_email', token=token, _external=True)
    msg = Message('Confirm Your Email', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    msg.body = f'Click to confirm: {link}'
    mail.send(msg)

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first_or_404()
    user.is_verified = True
    db.session.commit()
    flash('Email verified! You can now log in.')
    return redirect(url_for('login'))

def send_reset_email(user):
    token = s.dumps(user.email, salt='password-reset')
    link = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    msg.body = f'Reset your password: {link}'
    mail.send(msg)

# Route to request password reset
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            flash('Password reset email sent.')
        else:
            flash('No account with that email.')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('The reset link is invalid or has expired.')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first_or_404()
    if request.method == 'POST':
        password = request.form['password']
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        flash('Password reset successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:;"
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

def is_blocked(blocker_id, blocked_id):
    block = Block.query.filter_by(blocker_id=blocker_id, blocked_id=blocked_id).first()
    return block and block.expires_at > datetime.utcnow()

@app.route('/report_post/<int:post_id>')
def report_post(post_id):
    post = Post.query.get_or_404(post_id)
    post.is_reported = True
    db.session.commit()
    flash('Post reported for review.')
    return redirect(url_for('feed'))

@app.route('/approve_post/<int:post_id>', methods=['POST'])
def approve_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    post = Post.query.get_or_404(post_id)
    post.is_reported = False
    db.session.commit()
    flash('Post approved.')
    return redirect(url_for('admin_panel'))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted.')
    return redirect(url_for('admin_panel'))

@app.route('/admin/ban/<int:user_id>/<duration>', methods=['POST'])
def ban_user(user_id, duration):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin = User.query.get(session['user_id'])
    if not admin or not admin.is_admin:
        abort(403)
    durations = {'day': 1, 'week': 7, 'permanent': None}
    days = durations.get(duration)
    expires_at = datetime.utcnow() + timedelta(days=days) if days else None
    ban = Ban.query.filter_by(user_id=user_id).first()
    if ban:
        ban.expires_at = expires_at
    else:
        ban = Ban(user_id=user_id, expires_at=expires_at)
        db.session.add(ban)
    db.session.commit()
    flash(f'User banned for {duration}.')
    return redirect(url_for('admin_panel'))

@app.route('/admin/unban/<int:user_id>', methods=['POST'])
def unban_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin = User.query.get(session['user_id'])
    if not admin or not admin.is_admin:
        abort(403)
    ban = Ban.query.filter_by(user_id=user_id).first()
    if ban:
        db.session.delete(ban)
        db.session.commit()
        flash('User unbanned.')
    return redirect(url_for('admin_panel'))


@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    notes = Notification.query.filter_by(user_id=session['user_id']).order_by(Notification.timestamp.desc()).all()
    return render_template('notifications.html', notifications=notes)

@app.route('/messages/<username>', methods=['GET', 'POST'])
def messages(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    recipient = User.query.filter_by(username=username).first_or_404()
    if request.method == 'POST':
        text = request.form.get('text')
        self_destruct = bool(request.form.get('self_destruct'))
        voice = request.files.get('voice')
        voice_filename = None
        if voice and voice.filename:
            voice_filename = secure_filename(voice.filename)
            voice.save(os.path.join(app.config['UPLOAD_FOLDER'], voice_filename))
        msg = Message(
            sender_id=session['user_id'],
            recipient_id=recipient.id,
            text=text,
            voice_filename=voice_filename,
            self_destruct=self_destruct
        )
        scheduled_at = request.form.get('scheduled_at')
        if scheduled_at:
            msg.scheduled_at = datetime.strptime(scheduled_at, "%Y-%m-%dT%H:%M")
            db.session.add(msg)
            db.session.commit()
            flash('Message scheduled.')
            return redirect(request.referrer)
    messages = Message.query.filter(
        (Message.sender_id == session['user_id']) | (Message.recipient_id == session['user_id'])
    ).order_by(Message.timestamp.desc()).all()
    return render_template('messages.html', recipient=recipient, messages=messages)

@app.route('/edit_message/<int:msg_id>', methods=['POST'])
def edit_message(msg_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    msg = Message.query.get_or_404(msg_id)
    if msg.sender_id != session['user_id']:
        abort(403)
    msg.text = request.form.get('text')
    db.session.commit()
    flash('Message edited.')
    return redirect(request.referrer)

@app.route('/delete_message/<int:msg_id>', methods=['POST'])
def delete_message(msg_id):
    msg = Message.query.get_or_404(msg_id)
    if msg.sender_id != session['user_id']:
        abort(403)
    db.session.delete(msg)
    db.session.commit()
    flash('Message deleted.')
    return redirect(request.referrer)

@app.route('/story/upload', methods=['GET', 'POST'])
def upload_story():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['story']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            expires_at = datetime.utcnow() + timedelta(hours=24)
            story = Story(user_id=session['user_id'], media_filename=filename, expires_at=expires_at)
            db.session.add(story)
            db.session.commit()
            # Start async review for harmful content
            Thread(target=async_review_story, args=(story.id,)).start()
            flash('Story uploaded!')
            return redirect(url_for('stories'))
    return render_template('upload_story.html')

@app.route('/stories')
def stories():
    now = datetime.utcnow()
    stories = Story.query.filter(Story.expires_at > now, Story.is_banned == False).all()
    return render_template('stories.html', stories=stories)

@app.route('/admin/warn_story/<int:story_id>', methods=['POST'])
def warn_story(story_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin = User.query.get(session['user_id'])
    if not admin or not admin.is_admin:
        abort(403)
    story = Story.query.get_or_404(story_id)
    if story.warning_count < 3:
        story.warning_count += 1
        db.session.commit()
        flash(f'Warning {story.warning_count}/3 issued to story.')
    else:
        flash('Story temporarily banned after 3 warnings.')
        story.is_banned = True
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/groups')
def groups():
    groups = Group.query.all()
    return render_template('groups.html', groups=groups)

@app.route('/group/<int:group_id>')
def group(group_id):
    group = Group.query.get_or_404(group_id)
    members = GroupMember.query.filter_by(group_id=group_id).all()
    return render_template('group.html', group=group, members=members)

@app.route('/group/join/<int:group_id>')
def join_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not GroupMember.query.filter_by(group_id=group_id, user_id=session['user_id']).first():
        db.session.add(GroupMember(group_id=group_id, user_id=session['user_id']))
        db.session.commit()
    flash('Joined group!')
    return redirect(url_for('group', group_id=group_id))

@app.route('/group/<int:group_id>/confess', methods=['GET', 'POST'])
def group_confess(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        text = request.form['text']
        confession = GroupConfession(group_id=group_id, text=text)
        db.session.add(confession)
        db.session.commit()
        flash('Your anonymous confession was submitted for review!')
        return redirect(url_for('group', group_id=group_id))
    return render_template('group_confess.html', group_id=group_id)

@app.route('/group/<int:group_id>/chat', methods=['GET', 'POST'])
def group_chat(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    group = Group.query.get_or_404(group_id)
    if request.method == 'POST':
        text = request.form['text']
        reply_to = request.form.get('reply_to')
        is_announcement = bool(request.form.get('is_announcement'))
        msg = GroupChatMessage(
            group_id=group_id,
            user_id=session['user_id'],
            text=text,
            reply_to_id=reply_to if reply_to else None,
            is_announcement=is_announcement
        )
        db.session.add(msg)
        db.session.commit()
        flash('Message sent!')
        return redirect(url_for('group_chat', group_id=group_id))
    messages = GroupChatMessage.query.filter_by(group_id=group_id).order_by(GroupChatMessage.timestamp.asc()).all()
    return render_template('group_chat.html', group=group, messages=messages)

@app.route('/onboarding')
def onboarding():
    return render_template('onboarding.html')


# (Removed CSS. Place these styles in your static CSS file or in a <style> block in your HTML templates.)
@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/cookie')
def cookie():
    return render_template('cookie.html')

# (Removed misplaced HTML/JS. Place the following in your HTML template before </body> if needed:)
# <!-- Add this just before </body> in your base template (e.g., base.html or register.html) -->
# <script>
# if ('serviceWorker' in navigator) {
#     window.addEventListener('load', function() {
#         navigator.serviceWorker.register('/static/service-worker.js')
#             .then(function(registration) {
#                 // Registration successful
#             })
#             .catch(function(error) {
#                 // Registration failed
#             });
#     });
# }
# </script>
from flask import request, jsonify

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/save_push_subscription', methods=['POST'])
@login_required
def save_push_subscription():
    sub = request.get_json()
    user = User.query.get(session['user_id'])
    user.push_subscription = json.dumps(sub)
    db.session.commit()
    return jsonify({'ok': True})




from pywebpush import webpush, WebPushException

def send_push(user, title, body, url='/'):
    sub = json.loads(user.push_subscription)
    try:
        webpush(
            subscription_info=sub,
            data=json.dumps({'title': title, 'body': body, 'url': url}),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={"sub": "mailto:your@email.com"}
        )
    except WebPushException as ex:
        print("Push failed:", ex)

# The following Dart/Flutter code was removed because it is not valid Python.
# If you need to use Firebase Messaging, place this code in your Flutter/Dart project, not in your Python backend.

# (Removed invalid JavaScript/React and CSS code. If needed, place this code in the appropriate frontend files.)

@app.route('/discover', methods=['GET', 'POST'])
def discover():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    results = []
    query = ''
    if request.method == 'POST':
        query = request.form['query']
        # Search Vybe Flow users
        results = User.query.filter(
            (User.username.ilike(f'%{query}%')) |
            (User.email.ilike(f'%{query}%')) |
            (User.bio.ilike(f'%{query}%'))
        ).all()
        # Optionally: Integrate with Facebook/Twitter/Snapchat APIs for universal search
        # (You would need to use their APIs and OAuth for this, not shown here for brevity)
    return render_template('discover.html', results=results, query=query)
def get_trending_users(limit=10):

    # Example: users with most followers
    trending = db.session.query(User, db.func.count(Follow.id).label('fcount'))\
        .join(Follow, Follow.followed_id == User.id)\
        .group_by(User.id)\
        .order_by(db.desc('fcount'))\
        .limit(limit).all()
    return [u for u, _ in trending]

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    posts = Post.query.filter_by(user_id=user.id).all()
    post_likes = {p.id: Like.query.filter_by(post_id=p.id).count() for p in posts}
    post_comments = {p.id: Comment.query.filter_by(post_id=p.id).count() for p in posts}
    follower_count = Follow.query.filter_by(followed_id=user.id).count()
    story_views = StoryView.query.join(Story, StoryView.story_id == Story.id)\
        .filter(Story.user_id == user.id).count()
    return render_template(
        'dashboard.html',
        posts=posts,
        post_likes=post_likes,
        post_comments=post_comments,
        follower_count=follower_count,
        story_views=story_views
    )

@app.route('/add_friend', methods=['POST'])
def add_friend():
    if 'user_id' not in session:
        return jsonify({'error': 'Login required'}), 401
    username = request.form['username']
    user = User.query.filter_by(username=username).first()
    if not user:
        # Try searching by social handles
        user = User.query.filter(
            (User.facebook_handle == username) |
            (User.instagram_handle == username) |
            (User.tiktok_handle == username) |
            (User.snapchat_handle == username)
        ).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    # Unlimited requests: no limit logic
    if not Follow.query.filter_by(follower_id=session['user_id'], followed_id=user.id).first():
        db.session.add(Follow(follower_id=session['user_id'], followed_id=user.id))
        db.session.commit()
        notify(user.id, f"{User.query.get(session['user_id']).username} sent you a friend/follow request!")
    return jsonify({'ok': True})

import re

SCAM_PATTERNS = [
    r'free\s+money', r'cash\s+app', r'bitcoin', r'giveaway', r'click\s+here', r'win\s+\$\d+'
]

def is_scam(text):
    text = text.lower()
    return any(re.search(pattern, text) for pattern in SCAM_PATTERNS)

import spacy

nlp = spacy.load("en_core_web_sm")

SCAM_KEYWORDS = ["free money", "cash app", "bitcoin", "giveaway", "click here", "win $"]

def is_scam_advanced(text):
    doc = nlp(text.lower())
    # Keyword check
    if any(kw in doc.text for kw in SCAM_KEYWORDS):
        return True
    # ML/NLP-based: add your own logic or use a trained model
    # Example: Use a cloud API or custom model for more advanced detection
    return False

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Login required'}), 401
    recipient_id = int(request.form['recipient_id'])
    text = request.form['text']
    if is_scam(text):
        # Block sender and notify
        block = Block(blocker_id=recipient_id, blocked_id=session['user_id'], expires_at=datetime.utcnow() + timedelta(days=3650))
        db.session.add(block)
        db.session.commit()
        notify(session['user_id'], "you got blocked bitch")
        notify(recipient_id, "you got blocked bitch")
        return jsonify({'error': 'Scam detected. You are blocked.'}), 403
    # ...normal message sending logic...

import requests

def search_facebook_user(access_token, query):
    url = f"https://graph.facebook.com/v19.0/search"
    params = {
        "q": query,
        "type": "user",
        "access_token": access_token
    }
    resp = requests.get(url, params=params)
    return resp.json()

@app.route('/link_social', methods=['POST'])
def link_social():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    user.facebook_handle = request.form.get('facebook')
    user.instagram_handle = request.form.get('instagram')
    user.tiktok_handle = request.form.get('tiktok')
    user.snapchat_handle = request.form.get('snapchat')
    db.session.commit()
    flash('Social accounts linked!')
    return redirect(url_for('account'))

import os
from werkzeug.utils import secure_filename

ALLOWED_THEME_VIDEO_EXTENSIONS = {'mp4', 'webm'}
THEME_VIDEO_FOLDER = os.path.join(app.static_folder, 'themes')

def allowed_theme_video(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_THEME_VIDEO_EXTENSIONS

@app.route('/upload_theme_video', methods=['POST'])
@login_required
def upload_theme_video():
    if 'theme_video' not in request.files:
        flash('No file part')
        return redirect(request.referrer)
    file = request.files['theme_video']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.referrer)
    if file and allowed_theme_video(file.filename):
        filename = secure_filename(f"{session['user_id']}_{file.filename}")
        filepath = os.path.join(THEME_VIDEO_FOLDER, filename)
        file.save(filepath)
        # Save the filename to the user's profile or story draft as needed
        user = User.query.get(session['user_id'])
        user.custom_theme_video = filename
        db.session.commit()
        flash('Theme video uploaded!')
        return redirect(url_for('story_create'))
    else:
        flash('Invalid file type. Only MP4 and WebM allowed.')
        return redirect(request.referrer)

@app.route('/create_story', methods=['POST'])
@login_required
def create_story():
    # ...existing story fields...
    theme_video_filename = None
    if 'theme_video' in request.files:
        file = request.files['theme_video']
        if file and file.filename and allowed_theme_video(file.filename):
            theme_video_filename = secure_filename(f"{session['user_id']}_{int(time.time())}_{file.filename}")
            file.save(os.path.join(THEME_VIDEO_FOLDER, theme_video_filename))
    # Create the story with the theme video filename
    story = Story(
        user_id=session['user_id'],
        # ...other fields...
        theme_video=theme_video_filename
    )
    db.session.add(story)
    db.session.commit()
    flash('Story posted!')
    return redirect(url_for('story_view', story_id=story.id))

@app.route('/appeal_ban', methods=['POST'])
@login_required
def appeal_ban():
    user = User.query.get(session['user_id'])
    if hasattr(user, 'is_banned') and user.is_banned:
        reason = request.form.get('appeal_reason', '')
        if 'Appeal' in globals():
            appeal = Appeal(user_id=user.id, reason=reason)
            db.session.add(appeal)
            db.session.commit()
        try:
            msg = Message(
                subject='Ban Appeal',
                sender=app.config['MAIL_USERNAME'],
                recipients=[app.config['MAIL_USERNAME']],
                body=f"User {user.username} (ID: {user.id}) appealed their ban:\n\n{reason}"
            )
            mail.send(msg)
        except Exception as e:
            print("Mail send failed:", e)
        flash('Your appeal has been submitted. Our team will review it soon.')
    return redirect(url_for('banned'))

@app.route('/banned')
@login_required
def banned():
    ban = Ban.query.filter_by(user_id=session['user_id']).first()
    reason = ban.reason if ban and ban.reason else "No reason specified."
    return render_template('banned.html', reason=reason)

@app.route('/react_comment/<int:comment_id>', methods=['POST'])
def react_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Login required'}), 401
    emoji = request.form.get('emoji')
    gif_url = request.form.get('gif_url')
    reaction = CommentReaction(
        comment_id=comment_id,
        user_id=session['user_id'],
        emoji=emoji,
        gif_url=gif_url
    )
    db.session.add(reaction)
    db.session.commit()
    return jsonify({'ok': True})

class Appeal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class StoryComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.String(255), nullable=True)
    gif_url = db.Column(db.String(255), nullable=True)
    music_url = db.Column(db.String(255), nullable=True)  # e.g., YouTube/Spotify link

@app.route('/story/<int:story_id>/comment', methods=['POST'])
@login_required
def comment_on_story(story_id):
    text = request.form.get('text')
    gif_url = request.form.get('gif_url')
    music_url = request.form.get('music_url')
    comment = StoryComment(
        story_id=story_id,
        user_id=session['user_id'],
        text=text,
        gif_url=gif_url,
        music_url=music_url
    )
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('story_view', story_id=story_id))

import requests

def get_instagram_friends(access_token, instagram_user_id):
    """
    Fetches followers for a business/creator Instagram account.
    """
    url = f"https://graph.instagram.com/{instagram_user_id}/followers"
    params = {
        "access_token": access_token,
        "fields": "username,id"
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        return data.get('data', [])
    else:
        print("Instagram API error:", response.text)
        return []

@app.route('/import_instagram_friends')
@login_required
def import_instagram_friends():
    user = User.query.get(session['user_id'])
    # You must have stored these during OAuth
    access_token = user.instagram_access_token
    instagram_user_id = user.instagram_user_id
    if not access_token or not instagram_user_id:
        flash("Instagram account not linked or missing permissions.")
        return redirect(url_for('account'))
    friends = get_instagram_friends(access_token, instagram_user_id)
    # Optionally, match these usernames to Vybe Flow users and auto-follow them
    for friend in friends:
        friend_user = User.query.filter_by(instagram_handle=friend['username']).first()
        if friend_user and not Follow.query.filter_by(follower_id=user.id, followed_id=friend_user.id).first():
            db.session.add(Follow(follower_id=user.id, followed_id=friend_user.id))
    db.session.commit()
    flash(f"Imported {len(friends)} Instagram friends!")
    return redirect(url_for('account'))


if __name__ == '__main__':
    try:
        print("Starting VybeFlow application...")
        with app.app_context():
            print("Creating database tables...")
            db.create_all()
            print("Database tables created successfully!")
        print("Starting Flask server on http://0.0.0.0:5000")
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"Error starting VybeFlow: {e}")
        import traceback
        traceback.print_exc()


