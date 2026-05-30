"""
ML Signal Wrapper
-----------------
Loads the existing Gradient Boosting Classifier (model.pkl) and exposes
its prediction as ONE signal among many — not the only verdict.

Gracefully degrades if model.pkl is missing.
"""

import os
import pickle
import warnings

import numpy as np

warnings.filterwarnings("ignore")

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "pickle", "model.pkl")
_model = None
_load_error = None


def _try_load():
    global _model, _load_error
    if _model is not None or _load_error is not None:
        return
    try:
        with open(_MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    except Exception as e:
        _load_error = str(e)[:120]


def predict(url: str) -> dict:
    """
    Run the legacy feature extractor + GBC model and return:
        {
          "phishing_probability": float (0..1),
          "score": int (0..100),
          "available": bool,
          "detail": str
        }
    """
    _try_load()
    if _model is None:
        return {"phishing_probability": None, "score": 0,
                "available": False,
                "detail": f"Model not loaded: {_load_error or 'pickle/model.pkl missing'}"}

    try:
        # Import here so a missing FeatureExtraction doesn't break the rest
        from feature import FeatureExtraction
        feats = FeatureExtraction(url).getFeaturesList()
        x = np.array(feats).reshape(1, 30)
        proba = _model.predict_proba(x)[0]
        # In this dataset: index 0 = phishing (-1), index 1 = legitimate (1)
        phishing_prob = float(proba[0])
        return {
            "phishing_probability": phishing_prob,
            "score": int(round(phishing_prob * 100)),
            "available": True,
            "detail": f"GBC confidence: {phishing_prob*100:.1f}% phishing"
        }
    except Exception as e:
        return {"phishing_probability": None, "score": 0,
                "available": False,
                "detail": f"Prediction failed: {str(e)[:100]}"}
