from flask import Flask, request, jsonify
from pymongo import MongoClient
import bcrypt
import jwt
import os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

MONGODB_URI = os.getenv('MONGODB_URI')
JWT_SECRET = os.getenv('JWT_SECRET')
PORT = int(os.getenv('PORT', 5001))

client = MongoClient(MONGODB_URI)
db = client.get_database()
users_collection = db.users
transactions_collection = db.transactions


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        role = request.headers.get('X-Role')
        if role != 'Admin':
            return jsonify({'error': 'Service-level authorization failed'}), 403
        return f(*args, **kwargs)

    return decorated_function


@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username, password, role = data.get('username'), data.get('password'), data.get('role', 'user')
        if not username or not password: return jsonify({'error': 'Username and password required'}), 400
        if users_collection.find_one({'username': username}): return jsonify({'error': 'User already exists'}), 409
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_data = {'username': username, 'password': hashed_password, 'role': role, 'created_at': datetime.utcnow()}
        result = users_collection.insert_one(user_data)
        return jsonify({'message': 'User created', 'user_id': str(result.inserted_id)}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username, password = data.get('username'), data.get('password')
        if not username or not password: return jsonify({'error': 'Username and password required'}), 400
        user = users_collection.find_one({'username': username})
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        payload = {
            'Username': username, 'Role': user['role'], 'Issuer': 'ExpenseTracker',
            'exp': datetime.utcnow() + timedelta(days=1), 'iat': datetime.utcnow()
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        users_collection.update_one({'username': username}, {'$set': {'last_login': datetime.utcnow()}})
        return jsonify({'token': token, 'user': {'username': username, 'role': user['role']}}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/stats/users', methods=['GET'])
@admin_required
def get_user_stats():
    try:
        total_users = users_collection.count_documents({})
        last_24h = datetime.utcnow() - timedelta(hours=24)
        active_users = users_collection.count_documents({'last_login': {'$gte': last_24h}})
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
        return jsonify({'total_transactions': total_transactions}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)
