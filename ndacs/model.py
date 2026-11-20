"""
Hybrid CNN-LSTM intrusion detection model.

Each flow (40 features) is treated as a 1-D sequence:
  * Conv1D layers learn local patterns between neighbouring features
    (e.g. packet-length statistics, IAT statistics),
  * the LSTM learns longer-range dependencies across the whole feature vector,
  * a softmax layer outputs one probability per attack family.
"""
import json
import os

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import joblib
import numpy as np

import config
from ndacs.features import FEATURES, transform

MODEL_PATH = config.MODEL_DIR / "cnn_lstm.keras"
SCALER_PATH = config.MODEL_DIR / "scaler.joblib"
META_PATH = config.MODEL_DIR / "meta.json"
BACKGROUND_PATH = config.MODEL_DIR / "background.npy"


def build_cnn_lstm(n_features, n_classes, lr=1e-3):
    from tensorflow import keras
    from tensorflow.keras import layers

    inp = keras.Input(shape=(n_features, 1), name="flow_features")
    x = layers.Conv1D(64, 3, padding="same", activation="relu")(inp)
    x = layers.Conv1D(64, 3, padding="same", activation="relu")(x)
    x = layers.MaxPooling1D(2)(x)
    x = layers.Dropout(0.2)(x)
    x = layers.Conv1D(128, 3, padding="same", activation="relu")(x)
    x = layers.MaxPooling1D(2)(x)
    x = layers.Dropout(0.2)(x)
    x = layers.LSTM(64, return_sequences=True)(x)
    x = layers.LSTM(32)(x)
    x = layers.Dropout(0.3)(x)
    x = layers.Dense(64, activation="relu")(x)
    out = layers.Dense(n_classes, activation="softmax", name="attack_class")(x)

    model = keras.Model(inp, out, name="NDACS_CNN_LSTM")
    model.compile(optimizer=keras.optimizers.Adam(lr),
                  loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    return model


class Detector:
    """Loads the trained model and classifies flow feature vectors."""

    def __init__(self):
        from tensorflow import keras
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"No trained model at {MODEL_PATH}. Run scripts/train.py first.")
        self.model = keras.models.load_model(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.meta = json.loads(META_PATH.read_text())
        self.classes = self.meta["classes"]
        self.features = self.meta.get("features", FEATURES)
        self.benign_idx = self.classes.index("BENIGN") if "BENIGN" in self.classes else -1
        self.background = np.load(BACKGROUND_PATH) if BACKGROUND_PATH.exists() else None
        # warm-up so the first real prediction is fast
        self.predict_scaled(np.zeros((1, len(self.features))))

    # raw feature matrix -> scaled matrix
    def scale(self, X_raw):
        return self.scaler.transform(transform(X_raw)).astype(np.float32)

    def predict_scaled(self, Xs):
        Xs = np.asarray(Xs, dtype=np.float32).reshape(-1, len(self.features), 1)
        if len(Xs) <= 256:
            return self.model(Xs, training=False).numpy()
        return self.model.predict(Xs, verbose=0, batch_size=1024)

    def predict(self, X_raw):
        """Returns (labels, confidences, probability matrix)."""
        probs = self.predict_scaled(self.scale(X_raw))
        idx = probs.argmax(axis=1)
        return [self.classes[i] for i in idx], probs.max(axis=1), probs
