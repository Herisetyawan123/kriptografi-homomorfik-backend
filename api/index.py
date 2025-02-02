from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
import jwt
import datetime
from functools import wraps
import os
import random
import sympy
from flask_cors import CORS



# 1️⃣ Generate Paillier Key Pair
def generate_keys():
    p = sympy.randprime(100, 500)
    q = sympy.randprime(100, 500)
    n = p * q
    g = n + 1  # Standard choice for g
    λ = (p - 1) * (q - 1) // sympy.gcd(p - 1, q - 1)
    μ = pow(λ, -1, n)  # Modular inverse of λ mod n
    return (n, g), (λ, μ, n)

# 2️⃣ Enkripsi dengan Paillier
def encrypt(m, public_key):
    n, g = public_key
    r = random.randint(1, n - 1)
    c = (pow(g, m, n**2) * pow(r, n, n**2)) % (n**2)
    return c

# 3️⃣ Dekripsi dengan Paillier
def decrypt(c, private_key):
    λ, μ, n = private_key
    λ = int(λ)  # Convert to Python int
    μ = int(μ)  # Convert to Python int
    n = int(n)  # Convert to Python int
    c = int(c)  # Convert to Python int
    x = pow(c, λ, n**2)
    L = (x - 1) // n  # L function
    m = (L * μ) % n
    return m

# public_key, private_key = generate_keys()
public_key, private_key = (127723, 127724), (3024, 19471, 127723)

# Load environment variables from .env
load_dotenv()

env_db_uri = os.getenv('DATABASE_URL', 'postgresql://username:password@host:port/database')
env_secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

app = Flask(__name__)
CORS(app) 
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

class Savings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    balance_encrypted = db.Column(db.String, nullable=False)

    user = db.relationship('Users', backref=db.backref('savings', lazy=True))

class Transactions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    types = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    amount_enc = db.Column(db.String, nullable=False)

    user = db.relationship('Users', backref=db.backref('transactions', lazy=True))

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(500), nullable=False, unique=True)
    blacklisted_on = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, token, user_id):
        self.token = token
        self.user_id = user_id

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        if token.startswith("Bearer "):
            token = token.split(" ")[1]

        # Cek apakah token sudah di-blacklist
        blacklisted = TokenBlocklist.query.filter_by(token=token).first()
        if blacklisted:
            return jsonify({'message': 'Token has been revoked!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = Users.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found!'}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated




@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/')
def index():
    return jsonify({'message': "selamat datang di api"}), 200

@app.route('/key')
def key():
    return jsonify({'message': "selamat datang di api", "key": [public_key, private_key]}), 200

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
 
    # Buat user baru
    new_user = Users(name=name, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    new_saving = Savings(
        user_id=new_user.id,
        balance_encrypted=encrypt(0, public_key)
    )
    db.session.add(new_saving)
    db.session.commit()

    return jsonify({
        'message': 'User registered successfully',
        'user': {
            'id': new_user.id,
            'name': new_user.name,
            'email': new_user.email
        },
        'saving': {
            'user_id': new_saving.user_id,
            'balance_encrypted': new_saving.balance_encrypted
        }
    }), 201

# Login Endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Validasi input
    if not data.get('email') or not data.get('password'):
        return jsonify({'message': 'All fields are required'}), 400
    
    email = data['email']
    password = data['password']
    user = Users.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        # Blacklist semua token lama dari user ini
        TokenBlocklist.query.filter_by(user_id=user.id).delete()
        db.session.commit()

        # Generate JWT Token baru
        token = jwt.encode(
            {'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, 
            app.config['SECRET_KEY'], 
            algorithm='HS256'
        )

        return jsonify({'message': 'Login successful', 'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# 4️⃣ Operasi Homomorfik: Penjumlahan
def homomorphic_addition(c1, c2, n):
    return (c1 * c2) % (n**2)

@app.route('/api/dashboard', methods=['GET'])
@token_required
def dashboard(current_user):
        # Data asli
    a, b = 15, 10

    # Enkripsi data
    enc_a = encrypt(a, public_key)
    enc_b = encrypt(b, public_key)

    n = public_key[0]
    
    enc_sum = homomorphic_addition(enc_a, enc_b, n)
    print(private_key)
    dec_sum = decrypt(current_user.savings[0].balance_encrypted, private_key)
    return jsonify({
        'message': f'Welcome {current_user.name}!',
        'user': {
            'id': current_user.id,
            'name': current_user.name,
            'email': current_user.email
        },
        'saving': {
            'balance': decrypt(current_user.savings[0].balance_encrypted, private_key) if current_user.savings else 0.0
        }
    }), 200

@app.route('/api/logout', methods=['POST'])
@token_required
def logout(current_user):
    token = request.headers.get('Authorization').split(" ")[1]  # Ambil token dari header
    blacklisted_token = TokenBlocklist(token=token, user_id=current_user.id)

    db.session.add(blacklisted_token)
    db.session.commit()

    return jsonify({'message': 'Logged out successfully, token revoked!'}), 200

# Fungsi untuk mendapatkan enkripsi nilai negatif
def encrypt_negative(m, public_key):
    return encrypt(-m, public_key) 

def subtract(m1, m2, public_key, private_key):
    # Enkripsi nilai m1
    c1 = encrypt(m1, public_key)
    
    # Enkripsi nilai negatif m2
    c2_negative = encrypt_negative(m2, public_key)
    
    # Menghitung hasil pengurangan
    c_difference = (c1 * c2_negative) % (public_key[0] ** 2)
    
    # Dekripsi hasil pengurangan
    decrypted_difference = decrypt(c_difference, private_key)
    
    return c_difference, decrypted_difference

# Fungsi untuk menjumlahkan dua nilai
def add(m1, m2, public_key, private_key):
    # Enkripsi nilai m1 dan m2
    c1 = encrypt(m1, public_key)

    c2 = encrypt(m2, public_key)
    
    # Menghitung hasil penjumlahan
    c_sum = (c1 * c2) % (public_key[0] ** 2)
    
    # Dekripsi hasil penjumlahan
    decrypted_sum = decrypt(c_sum, private_key)
    
    return c_sum, decrypted_sum

@app.route('/api/topup', methods=['POST'])
@token_required
def topup(current_user):
    data = request.get_json()
    amount = int(data['amount'])
    description = data['description']
    
    user_savings = Savings.query.filter_by(user_id=current_user.id).first()

    if not user_savings:
        return jsonify({'message': 'User has no savings account'}), 404

    # Dekripsi saldo lama
    old_balances = decrypt(int(user_savings.balance_encrypted), private_key)
    amount_enc = encrypt(amount, public_key)

    # Enkripsi jumlah baru menggunakan operasi homomorfik
    new_balance_enc, new = add(old_balances, amount, public_key, private_key)

     # Simpan hasil enkripsi ke database
    user_savings.balance_encrypted = new_balance_enc
    db.session.commit()

    # Menambahkan transaksi ke tabel Transactions
    new_transaction = Transactions(
        user_id=current_user.id,
        types='topup',  # Tipe transaksi
        amount_enc=amount_enc,
        description=description
    )
    
    db.session.add(new_transaction)
    db.session.commit()

    return jsonify({
            'message': f'Successfully topped up {amount}',
            'balance': decrypt(int(user_savings.balance_encrypted), private_key),
            }
        ), 200

@app.route('/api/withdraw', methods=['POST'])
@token_required
def withdraw(current_user):
    data = request.get_json()
    amount = int(data['amount'])
    description = data['description']
    
    user_savings = Savings.query.filter_by(user_id=current_user.id).first()

    if not user_savings:
        return jsonify({'message': 'User has no savings account'}), 404

    # Dekripsi saldo lama
    old_balances = decrypt(int(user_savings.balance_encrypted), private_key)
    if amount > old_balances:
        return jsonify({
            "message": "Saldo is not enough"
        }), 404
    amount_enc = encrypt(amount, public_key)

    # Enkripsi jumlah baru menggunakan operasi homomorfik
    new_balance_enc, new = subtract(old_balances, amount, public_key, private_key)

     # Simpan hasil enkripsi ke database
    user_savings.balance_encrypted = new_balance_enc
    db.session.commit()

    # Menambahkan transaksi ke tabel Transactions
    new_transaction = Transactions(
        user_id=current_user.id,
        types='withdraw',  # Tipe transaksi
        amount_enc=amount_enc, 
        description=description
    )
    
    db.session.add(new_transaction)
    db.session.commit()

    return jsonify({
            'message': f'Successfully topped up {amount}',
            'balance': decrypt(int(user_savings.balance_encrypted), private_key),
            }
        ), 200

@app.route('/api/transactions', methods=['GET'])
@token_required
def transactions(current_user):    
    user_transactions = Transactions.query.filter_by(user_id=current_user.id)
    user_transactions = [
        {
            'id': user_transaction.id, 
            'type': user_transaction.types, 
            'amount': decrypt(user_transaction.amount_enc, private_key)
        } for user_transaction in user_transactions
    ]

    return jsonify({
            'message': f'Successfully get data',
            'data': user_transactions,
            }
        ), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
