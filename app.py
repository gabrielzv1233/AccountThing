from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import requests
import socket
import os

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=text')
        if response.status_code == 200:
            return response.text
        else:
            return "0.0.0.0"
    except Exception as e:
        print(f"Cannot get public IP: {e}")
        return "0.0.0.0"

def get_local_ip():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        print(f"Cannot get local IP: {e}")
        return "127.0.0.1"

app = Flask(__name__)
port = 80
app.config['SECRET_KEY'] = f"{get_public_ip()}:{port}-{get_local_ip()}:{port}"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "You need to be logged in to access this page."


ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'password'  


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)  

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('signup'))
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:  
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password. Please try again.')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        if 'update_password' in request.form:
            new_password = request.form['new_password']  
            current_user.password = new_password
            db.session.commit()
            flash('Password updated successfully!')
        elif 'delete_account' in request.form:
            db.session.delete(current_user)
            db.session.commit()
            flash('Account deleted successfully.')
            return redirect(url_for('index'))
    return render_template('account.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/admin')
def admin():
    if 'admin_logged_in' not in session or not session['admin_logged_in']:
        return redirect(url_for('admin_login'))
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials.')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session or not session['admin_logged_in']:
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')

@app.route('/admin/db', methods=['GET', 'POST'])
def admin_db():
    if 'admin_logged_in' not in session or not session['admin_logged_in']:
        return redirect(url_for('admin_login'))

    users = User.query.all()

    if request.method == 'POST':
        
        delete_ids = request.form.get('delete_ids')
        if delete_ids:
            for user_id in delete_ids.split(','):
                user = User.query.get(user_id)
                if user:
                    db.session.delete(user)

        
        db.session.commit()

        
        for user in users:
            user_id = str(user.id)
            new_username = request.form.get(f'username_{user_id}')
            new_password = request.form.get(f'password_{user_id}')
            if new_username:
                user.username = new_username
            if new_password:
                user.password = new_password

        new_user_keys = [key for key in request.form if key.startswith('username_new_')]
        for key in new_user_keys:
            new_user_id = key.split('_')[-1]
            new_username = request.form.get(f'username_new_{new_user_id}')
            new_password = request.form.get(f'password_new_{new_user_id}')
            if new_username and new_password:
                new_user = User(username=new_username, password=new_password)
                db.session.add(new_user)

        
        db.session.commit()
        flash('Database updated successfully!')

    return render_template('admin_db.html', users=User.query.all())

@app.route('/admin/logout')
def admin_logout():
    session['admin_logged_in'] = False
    return redirect(url_for('admin_login'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(401)
def unauthorized(e):
    return render_template('401.html'), 401


with app.app_context():
    if not os.path.exists('database.db'):
        db.create_all()
        print("Database created successfully!")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=True)
