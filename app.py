import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vybeflow.db'
db = SQLAlchemy(app)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

class PostForm(FlaskForm):
    content = TextAreaField('What\'s on your mind?', validators=[DataRequired()])
    submit = SubmitField('Post')

@app.route('/feed', methods=['GET', 'POST'])
def feed():
    form = PostForm()
    if form.validate_on_submit():
        new_post = Post(content=form.content.data)
        db.session.add(new_post)
        db.session.commit()
        flash('Post created!')
        return redirect(url_for('feed'))
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('feed.html', form=form, posts=posts)

@app.route('/')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)