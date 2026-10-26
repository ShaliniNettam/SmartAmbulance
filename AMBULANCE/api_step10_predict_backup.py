# ============================================================
# SMART AMBULANCE - FASTAPI BACKEND
# ============================================================

from fastapi import FastAPI
from pydantic import BaseModel

from predict import predict_risk


# ============================================================
# CREATE API
# ============================================================

app = FastAPI(
    title="Smart Ambulance API",
    description="Phase 1 Emergency Healthcare Backend",
    version="1.0.0"
)


# ============================================================
# INPUT DATA MODEL
# ============================================================

class VitalSignsRequest(BaseModel):

    sequence: list[list[float]]


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():

    return {
        "message": "Smart Ambulance API is running",
        "status": "active"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ============================================================
# RISK PREDICTION
# ============================================================

@app.post("/predict")
def predict(request: VitalSignsRequest):

    result = predict_risk(
        request.sequence
    )

    return {
        "risk": result["risk"],
        "probabilities": result["probabilities"],
        "inference_time_ms": result["inference_time_ms"]
    }