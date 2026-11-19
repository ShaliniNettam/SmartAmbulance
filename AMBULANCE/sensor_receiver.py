
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
import requests
import time

app = FastAPI(
    title="Smart Ambulance - Live Sensor Receiver",
    description="Receives MAX30102 readings and forwards them securely",
    version="2.0.0"
)

AMBULANCE_SENSOR_URL = "http://127.0.0.1:8000/sensor-event"
FORWARD_INTERVAL_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 20

class SensorReading(BaseModel):
    heart_rate: float = Field(gt=0, le=250)
    spo2: float = Field(gt=0, le=100)
    device: str = "MAX30102"
    timestamp: Optional[str] = None


latest_reading = None
reading_history = []
last_forward_attempt = 0.0


@app.get("/")
def root():
    return {
        "message": "MAX30102 Sensor Receiver is running",
        "status": "active"
    }


@app.post("/sensor-data")
def receive_sensor_data(reading: SensorReading):
    global latest_reading, last_forward_attempt

    record = reading.model_dump()
    record["received_at"] = datetime.now(timezone.utc).isoformat()
    record["hospital_delivery"] = "pending"

    latest_reading = record
    reading_history.append(record)

    if len(reading_history) > 100:
        reading_history.pop(0)

    print("Received MAX30102 reading:", record)

    current_time = time.monotonic()

    if current_time - last_forward_attempt >= FORWARD_INTERVAL_SECONDS:

        # Do not forward physiologically implausible or
        # out-of-range sensor values.
        if not 30 <= reading.heart_rate <= 220 or not 70 <= reading.spo2 <= 100:
            record["hospital_delivery"] = "skipped_invalid_range"
            print("Sensor reading not forwarded: outside accepted range.")

        else:
            # Throttle attempts to avoid flooding the API.
            last_forward_attempt = current_time

            try:
                response = requests.post(
                    AMBULANCE_SENSOR_URL,
                    json={
                        "heart_rate": reading.heart_rate,
                        "spo2": reading.spo2,
                        "device": reading.device,
                        "timestamp": reading.timestamp
                    },
                    timeout=REQUEST_TIMEOUT_SECONDS
                )

                response.raise_for_status()
                result = response.json()

                record["hospital_delivery"] = "success"
                record["hospital_event_id"] = result.get("event_id")

                print(
                    "Hospital delivery successful:",
                    result.get("event_id")
                )

            except requests.RequestException as exc:
                record["hospital_delivery"] = "failed"
                print("Hospital forwarding error:", str(exc))

            except ValueError as exc:
                record["hospital_delivery"] = "failed"
                print("Invalid Ambulance API response:", str(exc))

    else:
        record["hospital_delivery"] = "waiting_for_next_interval"

    return {
        "status": "received",
        "message": "Sensor reading received successfully",
        "data": record
    }


@app.get("/latest")
def get_latest_reading():
    if latest_reading is None:
        raise HTTPException(
            status_code=404,
            detail="No sensor readings received yet"
        )

    return latest_reading


@app.get("/history")
def get_reading_history():
    return {
        "count": len(reading_history),
        "readings": reading_history
    }
