"""
Explainable AI layer: explains WHY a flow was classified as an attack.

Methods
  shap      - SHAP KernelExplainer (Shapley values, model-agnostic)   [default]
  lime      - LIME tabular explainer (local surrogate model)
  occlusion - fast fallback: replace each feature with a "normal" value and
              measure the drop in attack probability
Each explanation lists the top features, their real values and how strongly
they pushed the decision towards the predicted class, plus a plain-English text.
"""
import logging

import numpy as np

from ndacs.features import FEATURE_HINTS

log = logging.getLogger("ndacs.xai")


def _fmt(name, v):
    if "Duration" in name or "IAT" in name:
        if v >= 1e6:
            return f"{v/1e6:.2f} s"
        if v >= 1e3:
            return f"{v/1e3:.1f} ms"
        return f"{v:.0f} µs"
    if name.endswith("/s"):
        return f"{v:,.1f}"
    if name == "Destination Port":
        return str(int(v))
    return f"{v:,.0f}" if float(v).is_integer() else f"{v:,.2f}"


class Explainer:
    def __init__(self, detector, method="shap", top_k=8):
        self.d = detector
        self.top_k = top_k
        self.method = method
        self.background = detector.background
        if self.background is None:
            log.warning("No background sample saved with the model - using occlusion explainer")
            self.method = "occlusion"
        if self.method == "shap":
            try:
                import shap  # noqa: F401
            except ImportError:
                log.warning("shap not installed - using occlusion explainer")
                self.method = "occlusion"
        if self.method == "lime":
            try:
                from lime.lime_tabular import LimeTabularExplainer
                self._lime = LimeTabularExplainer(self.background, feature_names=self.d.features,
                                                  class_names=self.d.classes, discretize_continuous=False)
            except ImportError:
                log.warning("lime not installed - using shap")
                self.method = "shap"

    def _f(self, X):
        return self.d.predict_scaled(np.asarray(X, dtype=np.float32))

    def explain(self, x_raw):
        x_raw = np.asarray(x_raw, dtype=np.float64)
        xs = self.d.scale(x_raw[None])
        probs = self._f(xs)[0]
        ci = int(probs.argmax())
        label = self.d.classes[ci]
        method = self.method
        try:
            if method == "shap":
                contrib = self._shap(xs, ci)
            elif method == "lime":
                contrib = self._lime_explain(xs, ci)
            else:
                contrib = self._occlusion(xs, ci)
        except Exception as e:  # never fail an alert because of XAI
            log.warning("%s explanation failed (%s) - falling back to occlusion", method, e)
            method, contrib = "occlusion", self._occlusion(xs, ci)

        order = np.argsort(-np.abs(contrib))[: self.top_k]
        factors = []
        for j in order:
            name = self.d.features[j]
            factors.append({
                "feature": name,
                "value": float(x_raw[j]),
                "display": _fmt(name, float(x_raw[j])),
                "contribution": float(contrib[j]),
                "hint": FEATURE_HINTS.get(name, ""),
            })
        top_probs = sorted(((self.d.classes[i], float(p)) for i, p in enumerate(probs)),
                           key=lambda t: -t[1])[:4]
        return {"method": method.upper(), "label": label, "confidence": float(probs[ci]),
                "probabilities": top_probs, "factors": factors,
                "text": self._text(label, float(probs[ci]), factors)}

    # -------------------------------------------------------------- methods
    def _shap(self, xs, ci):
        import shap
        f = lambda X: self._f(X)[:, ci]
        ex = shap.KernelExplainer(f, self.background)
        sv = ex.shap_values(xs, nsamples=150, silent=True)
        return np.asarray(sv).reshape(-1)[: xs.shape[1]]

    def _lime_explain(self, xs, ci):
        exp = self._lime.explain_instance(xs[0], self._f, labels=(ci,), num_features=xs.shape[1],
                                          num_samples=1000)
        contrib = np.zeros(xs.shape[1])
        for j, w in exp.as_map()[ci]:
            contrib[j] = w
        return contrib

    def _occlusion(self, xs, ci):
        base_val = np.zeros(xs.shape[1], dtype=np.float32) if self.background is None \
            else self.background.mean(0)
        X = np.repeat(xs, xs.shape[1], axis=0)
        X[np.arange(xs.shape[1]), np.arange(xs.shape[1])] = base_val
        p0 = self._f(xs)[0, ci]
        return p0 - self._f(X)[:, ci]

    # -------------------------------------------------------------- text
    @staticmethod
    def _text(label, conf, factors):
        pos = [f for f in factors if f["contribution"] > 0][:3]
        neg = [f for f in factors if f["contribution"] < 0][:1]
        if label == "BENIGN":
            s = f"Traffic looks normal ({conf*100:.1f}% confidence)."
        else:
            s = f"Flow classified as {label} with {conf*100:.1f}% confidence."
        if pos:
            reasons = "; ".join(
                f"{f['feature']} = {f['display']}" + (f" ({f['hint']})" if f["hint"] else "") for f in pos)
            s += f" Main evidence: {reasons}."
        if neg:
            f = neg[0]
            s += f" Strongest counter-evidence: {f['feature']} = {f['display']}."
        return s


def rule_explanation(label, text, facts=None):
    """Explanation object for behaviour/signature and honeypot detections."""
    return {"method": "RULE", "label": label, "confidence": 1.0, "probabilities": [],
            "factors": [{"feature": k, "value": v, "display": str(v), "contribution": 1.0, "hint": ""}
                        for k, v in (facts or {}).items()],
            "text": text}
