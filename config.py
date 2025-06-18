from dotenv import load_dotenv
import os
import certifi
from pymongo import MongoClient
import redis

# Load environment variables from .env file
load_dotenv()

# --- MongoDB Configuration ---
MONGODB_URI = os.getenv('MONGODB_URI')
try:
    # Connect to MongoDB using the full URI
    _mongo_client = MongoClient(
        MONGODB_URI,
        tls=True,
        tlsCAFile=certifi.where(),
        serverSelectionTimeoutMS=5000
    )

    # PyMongo's get_database() with no arguments will return the database
    # specified in the connection string ('expTracker' in your case).
    db = _mongo_client.get_database()

    # Verify connection is active
    _mongo_client.admin.command('ping')
    print(f"MongoDB connection successful to database '{db.name}'.")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    db = None


# --- Redis Configuration (for Redis Cloud) ---
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

try:
    # Initialize the Redis client with separate host, port, and password
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


# --- JWT and Port Configuration ---
JWT_SECRET = os.getenv('JWT_SECRET')
PORT = int(os.getenv('PORT', 5001))
