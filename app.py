# auth_service/app.py
from flask import Flask, request, jsonify
from pymongo import MongoClient
import bcrypt
import jwt
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# Configuration
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb+srv://RattanakVicboth:Dambo123@rattanakvicboth.7whe9xy.mongodb.net/ProjDB?retryWrites=true&w=majority&appName=RattanakVicboth')
JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret')
PORT = int(os.getenv('PORT', 5001))

# Database connection
client = MongoClient(MONGODB_URI)
db = client.get_database()
users_collection = db.users

@app.route('/health')
def health():
    return jsonify({'status': 'Auth Service running', 'port': PORT})

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')  # default role is 'user'

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        # Check if user exists
        if users_collection.find_one({'username': username}):
            return jsonify({'error': 'User already exists'}), 409

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create user
        user_data = {
            'username': username,
            'password': hashed_password,
            'role': role,
            'created_at': datetime.utcnow()
        }

        result = users_collection.insert_one(user_data)

        return jsonify({
            'message': 'User created successfully',
            'user_id': str(result.inserted_id)
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        # Find user
        user = users_collection.find_one({'username': username})
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        # Check password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return jsonify({'error': 'Invalid credentials'}), 401

        # Generate JWT
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
        return jsonify({'error': str(e)}), 500

@app.route('/refresh', methods=['POST'])
def refresh_token():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing token'}), 401

        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], options={"verify_exp": False})

        # Generate new token
        new_payload = {
            'Username': payload['Username'],
            'Role': payload['Role'],
            'Issuer': 'ExpenseTracker',
            'exp': datetime.utcnow() + timedelta(days=1),
            'iat': datetime.utcnow()
        }

        new_token = jwt.encode(new_payload, JWT_SECRET, algorithm='HS256')

        return jsonify({'token': new_token}), 200

    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)