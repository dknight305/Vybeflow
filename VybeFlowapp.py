from utils import notify

db = SQLAlchemy(app)

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

# --- Flask App Config: Security Hardening ---
app = Flask(__name__)
import os
from datetime import datetime, timedelta
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

db = SQLAlchemy(app)
CORS(app, supports_credentials=True, origins=["https://yourdomain.com"])  # Set your production domain



# --- Model Stubs for missing models ---
class LivePoll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer)
    question = db.Column(db.String(255))
    options = db.Column(db.Text)

class LivePollVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    option = db.Column(db.String(255))

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class GroupConfession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer)
    text = db.Column(db.String(1000))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class GroupChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    text = db.Column(db.String(1000))
    reply_to_id = db.Column(db.Integer, nullable=True)
    is_announcement = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class StoryView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    viewed_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- Advanced Livestream Features ---
# Live Reaction (emoji, heart, etc.)
class LiveReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(16), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Live Poll


from flask_sqlalchemy import SQLAlchemy

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

db = SQLAlchemy(app)
CORS(app, supports_credentials=True, origins=["https://yourdomain.com"])  # Set your production domain

import os
from datetime import datetime, timedelta
# --- Model Definitions (must come after db is initialized) ---
class LivePoll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer)
    question = db.Column(db.String(255))
    options = db.Column(db.Text)

class LivePollVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    option = db.Column(db.String(255))

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class GroupConfession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer)
    text = db.Column(db.String(1000))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class GroupChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    text = db.Column(db.String(1000))
    reply_to_id = db.Column(db.Integer, nullable=True)
    is_announcement = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class StoryView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    viewed_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- Advanced Livestream Features ---
class LiveReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(16), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class LiveQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question = db.Column(db.String(255), nullable=False)
    is_highlighted = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class VirtualGift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    gift_type = db.Column(db.String(32), nullable=False)
    amount = db.Column(db.Integer, default=1)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Achievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(255))
    earned_at = db.Column(db.DateTime, default=datetime.utcnow)

class CoStream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_ids = db.Column(db.Text, nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime, nullable=True)

class StreamOverlay(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    overlay_type = db.Column(db.String(32), nullable=False)
    data = db.Column(db.Text, nullable=True)

class StreamMusic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    track_url = db.Column(db.String(255), nullable=False)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ARFilter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    file_url = db.Column(db.String(255), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_public = db.Column(db.Boolean, default=True)

class VIPStreamAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    purchased_at = db.Column(db.DateTime, default=datetime.utcnow)

class StreamHighlight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    start_time = db.Column(db.Float, nullable=False)
    end_time = db.Column(db.Float, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LiveLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    city = db.Column(db.String(64), nullable=True)
    country = db.Column(db.String(64), nullable=True)


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
import os
import re
import json
import time
import traceback
from threading import Thread
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash
import spacy
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.contrib.google import make_google_blueprint, google

# --- Flask App Initialization ---


# --- Flask App Initialization ---


# The following code block was incorrectly indented and not inside any function.
# If this is meant to be a follow route, wrap it in a function as below:


# Ensure login_required is defined only once, outside of any route (already present elsewhere in the file)
from functools import wraps
from flask import session, redirect, url_for

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Properly define the follow_user route and function
@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    """Follow a user"""
    current_user_id = session['user_id']
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


from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy(app)
CORS(app, supports_credentials=True, origins=["https://yourdomain.com"])  # Set your production domain

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