from flask import Flask, render_template, redirect, url_for, flash, request
from models import db, Comment, Post, User
from jinja2 import TemplateNotFound
from datetime import datetime
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Create the Flask application instance
app = Flask(__name__)
# Set a secret key for session management, required for flash messages
app.secret_key = os.urandom(24)

# --- Post Comments ---
@app.route('/post/<int:post_id>/comments', methods=['GET', 'POST'])
def post_comments(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        content = request.form.get('comment')
        user_id = 1  # Replace with session user id
        if content:
            comment = Comment(post_id=post_id, user_id=user_id, content=content)
            db.session.add(comment)
            db.session.commit()
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.desc()).all()
    return render_template('comments.html', post_id=post_id, comments=comments)

# --- Music on Profile ---
@app.route('/profile/music', methods=['GET', 'POST'])
def profile_music():
    user_id = 1  # Replace with session user id
    user = User.query.get(user_id)
    if request.method == 'POST':
        music_file = request.files.get('music_file')
        if music_file:
            filename = f"static/uploads/{music_file.filename}"
            music_file.save(filename)
            user.avatar = filename  # For demo, store music path in avatar field
            db.session.commit()
    music_url = user.avatar if user and user.avatar else None
    return render_template('profile_music.html', music_url=music_url)

# --- Upload Emojis/3D Emojis ---
from flask_sqlalchemy import SQLAlchemy
class Emoji(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/emojis/upload', methods=['GET', 'POST'])
def upload_emoji():
    user_id = 1  # Replace with session user id
    if request.method == 'POST':
        emoji_file = request.files.get('emoji_file')
        if emoji_file:
            filename = f"static/emojis/{emoji_file.filename}"
            emoji_file.save(filename)
            emoji = Emoji(user_id=user_id, image_url=filename)
            db.session.add(emoji)
            db.session.commit()
    emojis = Emoji.query.filter_by(user_id=user_id).order_by(Emoji.created_at.desc()).all()
    return render_template('upload_emoji.html', emojis=emojis)

# --- Post Stories ---
class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text)
    media_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/stories', methods=['GET', 'POST'])
def stories():
    user_id = 1  # Replace with session user id
    if request.method == 'POST':
        story_text = request.form.get('story_text')
        story_media = request.files.get('story_media')
        media_url = None
        if story_media:
            filename = f"static/stories/{story_media.filename}"
            story_media.save(filename)
            media_url = filename
        story = Story(user_id=user_id, text=story_text, media_url=media_url)
        db.session.add(story)
        db.session.commit()
    recent_stories = Story.query.order_by(Story.created_at.desc()).limit(20).all()
    return render_template('stories.html', stories=recent_stories)

# --- Video Calling ---
@app.route('/video_call/<int:user_id>')
def video_call(user_id):
    # Stub for video calling feature
    return render_template('video_call.html', user_id=user_id)

# Default home route — sends users to the login page.
@app.route('/')
def home():
    """
    Default home route — sends users to the login page.
    """
    return redirect(url_for('login'))
def home():
    """
    Default home route — sends users to the login page.
    """
    return redirect(url_for('login'))


# Logout route
@app.route('/logout')
def logout():
    """
    Handles the user logout process.
    """
    # In a real app, you would clear the user's session here
    flash('You have been logged out successfully.', 'info')
    # Redirect to the login page or home page after logging out
    return redirect(url_for('login'))


# Register route
@app.route('/register', methods=['GET', 'POST'])
def is_scam_account(username, email):
    """
    Stub for AI scam detection. Replace with real model or API.
    Returns True if account is likely a scam.
    """
    scam_keywords = ['scam', 'fake', 'bot', 'fraud']
    if any(word in username.lower() for word in scam_keywords):
        return True
    if email.endswith('@spam.com'):
        return True
    # TODO: Integrate with real AI model or API
    return False

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Renders the registration page and handles sign-up logic.
    """
    if hasattr(app, 'request') and app.request.method == 'POST':
        username = app.request.form.get('username', '')
        email = app.request.form.get('email', '')
        if is_scam_account(username, email):
            flash('Account flagged as scam. Please use a real username/email.', 'danger')
            return redirect(url_for('register'))
        # Proceed with user creation
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    try:
        return render_template('register.html')
    except TemplateNotFound:
        return "<h1>Register page not found (missing template)</h1>", 500

# Facebook OAuth stub
@app.route('/auth/facebook')
def auth_facebook():
    """
    Stub for Facebook OAuth sign-up/login.
    """
    # Here you would integrate with Facebook OAuth
    flash('Facebook sign-up is not yet implemented.', 'info')
    return redirect(url_for('register'))

# Twitter OAuth stub
@app.route('/auth/twitter')
def auth_twitter():
    """
    Stub for Twitter OAuth sign-up/login.
    """
    # Here you would integrate with Twitter OAuth
    flash('Twitter sign-up is not yet implemented.', 'info')
    return redirect(url_for('register'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Example authentication logic
        username = form.username.data
        password = form.password.data
        flash(f"Welcome back, {username}!", "success")
        return redirect(url_for('feed'))
    return render_template('login.html', form=form)

# Forgot password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Page for handling forgotten passwords.
    """
    if request.method == 'POST':
        email = request.form.get('email')
        # Here you'd normally send a reset email or token
        flash(f"Password reset instructions sent to {email}.", "info")
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

# 404 (Not Found) error handler
@app.errorhandler(404)
def page_not_found(e):
    """
    Custom error handler for 404 errors.
    """
    try:
        return render_template('404.html'), 404
    except TemplateNotFound:
        return "<h1>404 - Page Not Found</h1>", 404

# 500 (Internal Server Error) error handler
@app.errorhandler(500)
def internal_server_error(e):
    """
    Custom error handler for 500 errors.
    """
    try:
        return render_template('500.html'), 500
    except TemplateNotFound:
        return "<h1>500 - Internal Server Error</h1>", 500


# --- Rap Battle Rooms, Voting, Leaderboards ---
@app.route('/battlerooms')
def battlerooms():
    # List all active battle rooms
    # rooms = BattleRoom.query.filter_by(is_active=True).all()
    return render_template('battlerooms.html')

@app.route('/battle/<int:battle_id>')
def battle(battle_id):
    # Show battle details and voting
    # battle = Battle.query.get_or_404(battle_id)
    return render_template('battle.html')

@app.route('/leaderboard')
def leaderboard():
    # Show top battlers and crews
    return render_template('leaderboard.html')

# --- Crew Creation and Membership ---
@app.route('/crews')
def crews():
    # List all crews
    return render_template('crews.html')

@app.route('/crew/<int:crew_id>')
def crew(crew_id):
    # Show crew details
    return render_template('crew.html')

@app.route('/join_crew/<int:crew_id>')
def join_crew(crew_id):
    # Join a crew
    flash('Joined crew!', 'success')
    return redirect(url_for('crew', crew_id=crew_id))

# --- Live Streaming Features ---
@app.route('/live')
def live():
    # List live streams
    return render_template('live.html')

@app.route('/stream/<int:stream_id>')
def stream(stream_id):
    # Show stream details
    return render_template('stream.html')

@app.route('/stream/<int:stream_id>/reaction', methods=['POST'])
def stream_reaction(stream_id):
    # Add a reaction to a stream
    return 'Reaction added'

@app.route('/stream/<int:stream_id>/poll', methods=['POST'])
def stream_poll(stream_id):
    # Create a poll in a stream
    return 'Poll created'

@app.route('/stream/<int:stream_id>/gift', methods=['POST'])
def stream_gift(stream_id):
    # Send a virtual gift
    return 'Gift sent'

@app.route('/stream/<int:stream_id>/overlay', methods=['POST'])
def stream_overlay(stream_id):
    # Add or update overlay
    return 'Overlay updated'

@app.route('/stream/<int:stream_id>/arfilter', methods=['POST'])
def stream_arfilter(stream_id):
    # Add AR filter
    return 'AR filter added'

@app.route('/stream/<int:stream_id>/music', methods=['POST'])
def stream_music(stream_id):
    # Add music track
    return 'Music added'

@app.route('/stream/<int:stream_id>/location', methods=['POST'])
def stream_location(stream_id):
    # Set live location
    return 'Location set'

@app.route('/stream/<int:stream_id>/highlight', methods=['POST'])
def stream_highlight(stream_id):
    # Create a stream highlight
    return 'Highlight created'

@app.route('/stream/<int:stream_id>/vip', methods=['POST'])
def stream_vip(stream_id):
    # Grant VIP access
    return 'VIP access granted'

@app.route('/stream/<int:stream_id>/costream', methods=['POST'])
def stream_costream(stream_id):
    # Start a co-stream
    return 'Co-stream started'

# --- Achievements, Gifts, Emojis, Stickers ---
@app.route('/achievements')
def achievements():
    # List user achievements
    return render_template('achievements.html')

@app.route('/gifts')
def gifts():
    # List available virtual gifts
    return render_template('gifts.html')

@app.route('/stickers')
def stickers():
    # List available stickers
    return render_template('stickers.html')

@app.route('/emojis')
def emojis():
    # List available emojis
    return render_template('emojis.html')

# --- Feed, Trending, Highlights ---
@app.route('/feed')
def feed():
    # Show main feed
    try:
        return render_template('corrected_feed.html')
    except TemplateNotFound:
        return "<h1>Feed page not found (missing template)</h1>", 500

@app.route('/trending')
def trending():
    # Show trending battles, posts, highlights
    return render_template('trending.html')

@app.route('/highlights')
def highlights():
    # Show stream highlights
    return render_template('highlights.html')

# --- Profile Themes/Avatars ---
@app.route('/profile/theme', methods=['GET', 'POST'])
def profile_theme():
    # Set or view profile theme
    return render_template('profile_theme.html')

@app.route('/profile/avatar', methods=['GET', 'POST'])
def profile_avatar():
    """
    Allow users to upload or select a custom avatar.
    """
    if hasattr(app, 'request') and app.request.method == 'POST':
        # file = app.request.files.get('avatar')
        # Save file and update user.avatar in database
        flash('Avatar updated!', 'success')
        return redirect(url_for('profile_avatar'))
    return render_template('profile_avatar.html')

@app.route('/example')
def example():
    return "Hello, World!"

if __name__ == '__main__':
    # Running the app in debug mode for development
    app.run(debug=True)
