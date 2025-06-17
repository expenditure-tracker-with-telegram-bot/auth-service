from flask import Flask, request, jsonify
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
from config import db, PORT, JWT_SECRET

app = Flask(__name__)

users_collection = db.users
transactions_collection = db.transactions

def verify_jwt_token(token):
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check both JWT token and role header for security
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401

        if payload.get('Role') != 'Admin':
            return jsonify({'error': 'Admin access required'}), 403

        return f(*args, **kwargs)
    return decorated_function

def auth_required(f):
    """General authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401

        # Add user info to request context
        request.user = payload
        return f(*args, **kwargs)
    return decorated_function

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')

        # Input validation
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        if users_collection.find_one({'username': username}):
            return jsonify({'error': 'User already exists'}), 409

        # Only allow admin role creation by existing admins
        if role == 'Admin':
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                payload = verify_jwt_token(token)
                if not payload or payload.get('Role') != 'Admin':
                    role = 'user'  # Force to user role if not admin
            else:
                role = 'user'

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_data = {
            'username': username,
            'password': hashed_password,
            'role': role,
            'created_at': datetime.utcnow(),
            'active': True
        }

        result = users_collection.insert_one(user_data)
        return jsonify({
            'message': 'User created successfully',
            'user_id': str(result.inserted_id)
        }), 201

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        user = users_collection.find_one({'username': username, 'active': True})

        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return jsonify({'error': 'Invalid credentials'}), 401

        # Create JWT payload
        payload = {
            'Username': username,
            'Role': user['role'],
            'Issuer': 'ExpenseTracker',
            'exp': datetime.utcnow() + timedelta(days=1),
            'iat': datetime.utcnow()
        }

        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')

        # Update last login
        users_collection.update_one(
            {'username': username},
            {'$set': {'last_login': datetime.utcnow()}}
        )

        return jsonify({
            'token': token,
            'user': {
                'username': username,
                'role': user['role']
            }
        }), 200

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/verify', methods=['POST'])
def verify_token():
    """Endpoint to verify token validity"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'valid': False, 'error': 'Missing authorization header'}), 401

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload:
            return jsonify({'valid': False, 'error': 'Invalid or expired token'}), 401

        return jsonify({
            'valid': True,
            'user': {
                'username': payload.get('Username'),
                'role': payload.get('Role')
            }
        }), 200

    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 500

@app.route('/admin/stats/users', methods=['GET'])
@admin_required
def get_user_stats():
    try:
        total_users = users_collection.count_documents({'active': True})
        last_24h = datetime.utcnow() - timedelta(hours=24)
        active_users = users_collection.count_documents({
            'last_login': {'$gte': last_24h},
            'active': True
        })

        return jsonify({
            'total_users': total_users,
            'active_users_last_24h': active_users
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/stats/transactions', methods=['GET'])
@admin_required
def get_transaction_stats():
    try:
        total_transactions = transactions_collection.count_documents({})
        last_24h = datetime.utcnow() - timedelta(hours=24)
        recent_transactions = transactions_collection.count_documents({
            'timestamp': {'$gte': last_24h}
        })

        return jsonify({
            'total_transactions': total_transactions,
            'recent_transactions_24h': recent_transactions
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/users', methods=['GET'])
@admin_required
def list_users():
    try:
        users = list(users_collection.find(
            {'active': True},
            {'password': 0}  # Exclude password field
        ))

        for user in users:
            user['_id'] = str(user['_id'])
            if 'created_at' in user:
                user['created_at'] = user['created_at'].isoformat()
            if 'last_login' in user:
                user['last_login'] = user['last_login'].isoformat()

        return jsonify({'users': users}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)