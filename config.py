from dotenv import load_dotenv
import os
import certifi
from pymongo import MongoClient
import redis

load_dotenv()

MONGODB_URI = os.getenv('MONGODB_URI')
try:
    _mongo_client = MongoClient(
        MONGODB_URI,
        tls=True,
        tlsCAFile=certifi.where(),
        serverSelectionTimeoutMS=5000
    )
    db = _mongo_client.get_database()
    _mongo_client.admin.command('ping')
    print(f"MongoDB connection successful to database '{db.name}'.")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    db = None


REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        decode_responses=True
    )
    redis_client.ping()
    print("Redis connection successful.")
except Exception as e:
    print(f"Error connecting to Redis: {e}")
    redis_client = None


JWT_SECRET = os.getenv('JWT_SECRET')
PORT = int(os.getenv('PORT', 5001))
