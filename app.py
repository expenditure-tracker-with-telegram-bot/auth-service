import uuid
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
import jwt
from flask import Flask, request, jsonify, g

from config import db, redis_client, JWT_SECRET, PORT

app = Flask(__name__)

users_collection = db.users


def get_user_from_headers(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        g.user = request.headers.get('X-User-Username')
        g.role = request.headers.get('X-User-Role')
        g.jti = request.headers.get('X-Token-Jti')
        g.exp = request.headers.get('X-Token-Exp')

        if not g.user or not g.jti:
            return jsonify({'error': 'Authentication information missing from request'}), 401
        return f(*args, **kwargs)

    return decorated_function


@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if users_collection.find_one({'username': username}):
        return jsonify({'error': 'User already exists'}), 409

    if role == 'Admin':
        requesting_role = request.headers.get('X-User-Role')
        if requesting_role != 'Admin':
            return jsonify({'error': 'Only an admin can create another admin'}), 403

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user_doc = {
        'username': username,
        'password': hashed,
        'role': role,
        'created_at': datetime.utcnow(),
    }
    res = users_collection.insert_one(user_doc)
    return jsonify({
        'message': 'User created successfully',
        'user_id': str(res.inserted_id)
    }), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    user = users_collection.find_one({'username': username})
    if not user or not bcrypt.checkpw(password.encode(), user['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    exp_time = datetime.utcnow() + timedelta(days=1)
    payload = {
        'username': user['username'],
        'role': user['role'],
        'exp': exp_time,
        'iat': datetime.utcnow(),
        'jti': str(uuid.uuid4())
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token}), 200


@app.route('/logout', methods=['POST'])
@get_user_from_headers
def logout():
    try:
        token_exp_timestamp = int(g.exp)
        now_timestamp = int(datetime.utcnow().timestamp())
        ttl = max(0, token_exp_timestamp - now_timestamp)

        if ttl > 0:
            redis_key = f"blacklist:{g.jti}"
            redis_client.setex(redis_key, ttl, "true")

        return jsonify({'message': 'Successfully logged out'}), 200
    except Exception as e:
        return jsonify({'error': 'Logout failed', 'details': str(e)}), 500


@app.route('/admin/users', methods=['GET'])
@get_user_from_headers
def list_users():
    if g.role != 'Admin':
        return jsonify({'error': 'Admin access required'}), 403

    users = list(users_collection.find({}, {'password': 0}))
    for u in users:
        u['_id'] = str(u['_id'])
        if 'created_at' in u:
            u['created_at'] = u['created_at'].isoformat()
    return jsonify({'users': users}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
