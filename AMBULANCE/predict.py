# ============================================================
# ATTENTION LAYER
# ============================================================
import os
import json
import time
import joblib
import numpy as np
import torch
import torch.nn as nn
class AttentionLayer(nn.Module):

    def __init__(self, hidden_dim):

        super().__init__()

        self.attention = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.Tanh(),
            nn.Linear(64, 1)
        )

    def forward(self, sequence_output):

        attention_scores = (
            self.attention(sequence_output)
            .squeeze(-1)
        )

        attention_weights = torch.softmax(
            attention_scores,
            dim=1
        )

        attention_weights_expanded = (
            attention_weights.unsqueeze(-1)
        )

        context_vector = torch.sum(
            sequence_output *
            attention_weights_expanded,
            dim=1
        )

        return (
            context_vector,
            attention_weights
        )


# ============================================================
# BI-LSTM + ATTENTION MODEL
# ============================================================

class BiLSTMAttention(nn.Module):

    def __init__(
        self,
        input_size=6,
        hidden_size=64,
        num_layers=2,
        num_classes=3,
        dropout=0.3
    ):

        super().__init__()

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=(
                dropout
                if num_layers > 1
                else 0
            )
        )

        lstm_output_dim = hidden_size * 2

        self.attention = AttentionLayer(
            lstm_output_dim
        )

        self.classifier = nn.Sequential(
            nn.Linear(
                lstm_output_dim,
                64
            ),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(
                64,
                num_classes
            )
        )

    def forward(self, x):

        lstm_output, _ = self.lstm(x)

        context_vector, attention_weights = (
            self.attention(lstm_output)
        )

        logits = self.classifier(
            context_vector
        )

        return logits
    # ============================================================
# LOAD MODEL AND SCALER
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model",
    "bilstm_attention_phase1.pth"
)

SCALER_PATH = os.path.join(
    BASE_DIR,
    "model",
    "phase1_scaler.pkl"
)

CONFIG_PATH = os.path.join(
    BASE_DIR,
    "model",
    "config.json"
)

# Load configuration
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

INPUT_SIZE = config["input_size"]
HIDDEN_SIZE = config["hidden_size"]
NUM_LAYERS = config["num_layers"]
NUM_CLASSES = config["num_classes"]
DROPOUT = config["dropout"]
SEQUENCE_LENGTH = config["sequence_length"]
CLASS_NAMES = config["class_names"]

# Device
device = torch.device("cpu")

# Create model
model = BiLSTMAttention(
    input_size=INPUT_SIZE,
    hidden_size=HIDDEN_SIZE,
    num_layers=NUM_LAYERS,
    num_classes=NUM_CLASSES,
    dropout=DROPOUT
)

# Load trained weights
model.load_state_dict(
    torch.load(
        MODEL_PATH,
        map_location=device
    )
)

model.to(device)
model.eval()

# Load scaler
scaler = joblib.load(SCALER_PATH)

print("Model and scaler loaded successfully!")


# ============================================================
# PREDICTION FUNCTION
# ============================================================

def predict_risk(sequence):

    sequence = np.asarray(
        sequence,
        dtype=np.float32
    )

    # Check input shape
    if sequence.shape != (
        SEQUENCE_LENGTH,
        INPUT_SIZE
    ):
        raise ValueError(
            f"Expected shape "
            f"({SEQUENCE_LENGTH}, {INPUT_SIZE}), "
            f"but received {sequence.shape}"
        )

    # Apply the same scaler used during training
    sequence_scaled = scaler.transform(sequence)

    # Convert to PyTorch tensor
    x = torch.tensor(
        sequence_scaled,
        dtype=torch.float32
    ).unsqueeze(0).to(device)

    # Measure inference time
    start_time = time.perf_counter()

    with torch.no_grad():

        logits = model(x)

        probabilities = torch.softmax(
            logits,
            dim=1
        )

        predicted_class = torch.argmax(
            probabilities,
            dim=1
        ).item()

    inference_time = (
        time.perf_counter() - start_time
    ) * 1000

    probabilities = (
        probabilities
        .cpu()
        .numpy()[0]
    )

    return {
        "risk": CLASS_NAMES[predicted_class],

        "probabilities": {
            CLASS_NAMES[i]: float(
                probabilities[i]
            )
            for i in range(NUM_CLASSES)
        },

        "inference_time_ms": round(
            inference_time,
            3
        )
    }
# ============================================================
# TEST STANDALONE PREDICTION
# ============================================================

if __name__ == "__main__":

    test_sequence = np.array([
        [80, 98, 18, 120, 80, 36.8],
        [82, 98, 18, 118, 79, 36.8],
        [81, 97, 19, 121, 81, 36.9],
        [83, 98, 18, 119, 80, 36.8],
        [80, 98, 17, 120, 80, 36.8],
        [82, 97, 18, 121, 81, 36.9],
        [81, 98, 18, 119, 79, 36.8],
        [80, 98, 17, 120, 80, 36.8],
        [82, 97, 18, 118, 80, 36.9],
        [81, 98, 18, 120, 81, 36.8]
    ])

    result = predict_risk(test_sequence)

    print("\n" + "=" * 60)
    print("SMART AMBULANCE - RISK PREDICTION")
    print("=" * 60)

    print("\nPredicted Risk:")
    print(result["risk"])

    print("\nProbabilities:")

    for risk, probability in result["probabilities"].items():
        print(f"  {risk}: {probability:.4f}")

    print(
        "\nInference Time:",
        result["inference_time_ms"],
        "ms"
    )

    print("=" * 60)