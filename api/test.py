from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
import jwt
import datetime
import os

# Load environment variables from .env
load_dotenv()

env_db_uri = os.getenv('DATABASE_URL', 'postgresql://username:password@host:port/database')
env_secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = env_db_uri  # Menggunakan variabel environment
app.config['SECRET_KEY'] = env_secret_key
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# Model User
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=False, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/')
def index():
    return jsonify({'message': "selamat datang di api"}), 200

# Get All Users Endpoint
@app.route('/api/users', methods=['GET'])
def get_users():
    users = Users.query.all()
    users_list = [{'id': user.id, 'name': user.name, 'email': user.email} for user in users]
    return jsonify({'users': users_list}), 200

# Register Endpoint
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data['name']
    email = data['email']
    password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = Users(name=name, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

# Login Endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    user = Users.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        # Generate JWT Token
        token = jwt.encode(
            {'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, 
            app.config['SECRET_KEY'], 
            algorithm='HS256'
        )
        return jsonify({'message': 'Login successful', 'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# Protected Dashboard Endpoint
@app.route('/api/dashboard', methods=['GET'])
@login_required
def dashboard():
    return jsonify({'message': f'Welcome {current_user.name}!'}), 200

# Logout Endpoint
@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
