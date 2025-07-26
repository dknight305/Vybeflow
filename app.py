import os
from flask import Flask, render_template

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
# ...other config...

@app.route('/')
def home():
    return render_template('home.html')

# ...other routes...

if __name__ == '__main__':
    app.run(debug=True)