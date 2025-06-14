from flask import Flask, render_template, redirect, url_for, request, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_limiter import Limiter
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_wtf.csrf import CSRFProtect
import random
from twilio.rest import Client
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@host/dbname'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your@email.com'
app.config['MAIL_PASSWORD'] = 'yourpassword'

# Twilio configuration
app.config['TWILIO_ACCOUNT_SID'] = 'your_account_sid'
app.config['TWILIO_AUTH_TOKEN'] = 'your_auth_token'
app.config['TWILIO_PHONE_NUMBER'] = '+1234567890'

# Secure session cookies
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True

from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

db = SQLAlchemy(app)
limiter = Limiter(app)
csrf = CSRFProtect(app)

facebook_bp = make_facebook_blueprint(
    client_id="YOUR_FACEBOOK_APP_ID",
    client_secret="YOUR_FACEBOOK_APP_SECRET",
    redirect_to="feed"
)
app.register_blueprint(facebook_bp, url_prefix="/facebook_login")

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
socketio = SocketIO(app)

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
    theme = db.Column(db.String(50), default='light')  # New field for user theme preference
    is_under_review = db.Column(db.Boolean, default=False)
    review_requested_at = db.Column(db.DateTime, nullable=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    media_filename = db.Column(db.String(120))
    media_type = db.Column(db.String(10), nullable=False)  # 'image', 'video', or 'live'
    caption = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    live_url = db.Column(db.String(255))  # New field for live stream URLs
    is_reported = db.Column(db.Boolean, default=False)  # New field to track reported posts
    is_private = db.Column(db.Boolean, default=False)  # New field for private posts

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

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
    reply_to_id = db.Column(db.Integer, db.ForeignKey('groupchatmessage.id'), nullable=True)  # For threaded replies
    is_announcement = db.Column(db.Boolean, default=False)  # For admin announcements
    is_pinned = db.Column(db.Boolean, default=False)        # For pinning messages

HATE_WORDS = {'hateword1', 'hateword2', 'hateword3'}  # Add real hate words here

def contains_hate(text):
    return any(word in text.lower() for word in HATE_WORDS)

def check_story_for_hate(story):
    if contains_hate(story.media_filename) or contains_hate(story.caption if hasattr(story, 'caption') else ''):
        story.warning_count += 1
        if story.warning_count >= 3:
            story.is_banned = True
            notify(story.user_id, "Your story was banned for repeated hate speech.")
        else:
            notify(story.user_id, f"Warning {story.warning_count}/3: Hate speech detected in your story.")
        db.session.commit()

def notify(user_id, message):
    n = Notification(user_id=user_id, message=message)
    db.session.add(n)
    db.session.commit()

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
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
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = RegistrationForm()  # Replace with LoginForm() if you have a separate login form
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
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
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/feed')
def feed():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('feed.html', posts=posts)

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
        post = Post(media_filename=filename, media_type=media_type, caption=caption, user_id=session['user_id'])
        db.session.add(post)
        db.session.commit()
        flash('Post uploaded successfully.')
        return redirect(url_for('feed'))
    return render_template('upload.html')

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.id.desc()).all()
    return render_template('profile.html', user=user, posts=posts)

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
    return redirect(request.referrer)

@app.route('/comment/<int:post_id>', methods=['POST'])
def comment(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    text = request.form['text']
    db.session.add(Comment(text=text, user_id=session['user_id'], post_id=post_id))
    db.session.commit()
    return redirect(request.referrer)

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

@app.route('/banned')
def banned():
    return render_template('banned.html')

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
            # Only show messages where scheduled_at is None or <= now
        db.session.add(msg)
        db.session.commit()
        notify(recipient.id, f"New message from {session['user_id']}")
        # Real-time notification placeholder (implement if using SocketIO or similar)
        flash('Message sent!')
        return redirect(url_for('messages', username=username))
    # Fetch messages between users
    msgs = Message.query.filter(
        ((Message.sender_id == session['user_id']) & (Message.recipient_id == recipient.id)) |
        ((Message.sender_id == recipient.id) & (Message.recipient_id == session['user_id']))
    ).order_by(Message.timestamp.asc()).all()
    # Mark as read and delete self-destructing messages
    for m in msgs:
        if m.recipient_id == session['user_id'] and not m.is_read:
            m.is_read = True
            if m.self_destruct:
                db.session.delete(m)
    db.session.commit()
    return render_template('messages.html', recipient=recipient, messages=msgs)

@app.route('/edit_message/<int:msg_id>', methods=['POST'])
def edit_message(msg_id):
    msg = Message.query.get_or_404(msg_id)
    if msg.sender_id != session['user_id']:
        abort(403)
    msg.text = request.form['text']
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

from datetime import datetime, timedelta

def process_account_reviews():
    one_day_ago = datetime.utcnow() - timedelta(days=1)
    users = User.query.filter(User.is_under_review == True, User.review_requested_at <= one_day_ago).all()
    for user in users:
        # If admin hasn't approved, auto-ban
        ban = Ban(user_id=user.id, expires_at=None)
        db.session.add(ban)
        user.is_under_review = False
        db.session.commit()
        notify(user.id, "Your account was banned after review.")

@app.route('/admin/review_accounts', methods=['GET', 'POST'])
def review_accounts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin = User.query.get(session['user_id'])
    if not admin or not admin.is_admin:
        abort(403)
    users = User.query.filter_by(is_under_review=True).all()
    if request.method == 'POST':
        user_id = int(request.form['user_id'])
        action = request.form['action']
        user = User.query.get(user_id)
        if action == 'approve':
            user.is_under_review = False
            user.review_requested_at = None
            db.session.commit()
            notify(user.id, "Your account has been approved by an administrator.")
            flash(f"User {user.username} approved.")
        elif action == 'ban':
            ban = Ban(user_id=user.id, expires_at=None)
            db.session.add(ban)
            user.is_under_review = False
            user.review_requested_at = None
            db.session.commit()
            notify(user.id, "Your account was banned after review.")
            flash(f"User {user.username} banned.")
        return redirect(url_for('review_accounts'))
    return render_template('review_accounts.html', users=users)
