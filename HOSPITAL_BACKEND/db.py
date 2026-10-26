
import os

import certifi
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DATABASE = os.getenv(
    "MONGODB_DATABASE",
    "smart_ambulance_hospital",
)

if not MONGODB_URI:
    raise ValueError("MONGODB_URI is missing from .env")

client = MongoClient(
    MONGODB_URI,
    serverSelectionTimeoutMS=15000,
    tlsCAFile=certifi.where(),
)

db = client[MONGODB_DATABASE]

# Store verified ambulance events.
hospital_events = db["hospital_events"]

# Store the hospital's independently accepted checkpoints.
hospital_checkpoints = db["hospital_checkpoints"]

try:
    client.admin.command("ping")

    print("MongoDB Atlas connection successful!")
    print("Database selected:", db.name)

    # Prevent duplicate event records.
    hospital_events.create_index(
        "event_id",
        unique=True,
    )

    # One checkpoint record per ambulance.
    hospital_checkpoints.create_index(
        "ambulance_id",
        unique=True,
    )

    print("Unique event_id index verified/created.")
    print("Unique ambulance_id checkpoint index verified/created.")

except Exception as error:
    client.close()
    raise ConnectionError(
        f"MongoDB Atlas connection failed: {error}"
    ) from error
