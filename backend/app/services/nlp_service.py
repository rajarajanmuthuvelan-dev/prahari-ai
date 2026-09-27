"""Rule-based and optional transformer analysis for email content."""
import logging
import re
from typing import Any, Protocol

from ..config import settings

logger = logging.getLogger(__name__)


class ModelInterface(Protocol):
    def analyze(self, subject: str, body: str) -> dict:
        """
        Returns:
          signals: list[str]      — human-readable signal descriptions
          score_contribution: int — 0-25 additive score
          model_used: str         — identifier string
          is_rule_based: bool
        """
        ...


class RuleBasedClassifier:
    """Transparent rule-based content classifier."""

    URGENCY = [
        "urgent", "immediately", "asap", "act now", "action required",
        "verify now", "suspended", "limited time", "expires", "24 hours",
        "account.*closed", "permanently",
    ]
    CREDENTIAL = [
        "click here", "log in", "sign in", "verify", "confirm",
        "update.*info", "enter.*password", "banking detail",
        "account access", "credential",
    ]
    THREAT = [
        "frozen", "terminated", "cancelled", "deleted", "unauthorized",
        "suspicious activity", "security alert", "warning",
    ]
    SOCIAL_ENG = [
        "dear customer", "dear user", "valued member",
        "congratulations", "you have been selected",
        "wire transfer", "bitcoin", "gift card",
    ]

    def _count(self, words: list[str], text: str) -> int:
        return sum(1 for w in words if re.search(w, text, re.IGNORECASE))

    def analyze(self, subject: str, body: str) -> dict:
        text = f"{subject} {body}".lower()
        signals: list[str] = []
        score = 0

        u = self._count(self.URGENCY, text)
        if u:
            pts = min(7, u * 2)
            score += pts
            signals.append(
                f"Urgency/pressure language ({u} pattern{'s' if u > 1 else ''}, +{pts} points)"
            )

        c = self._count(self.CREDENTIAL, text)
        if c:
            pts = min(5, c * 2)
            score += pts
            signals.append(
                f"Credential-harvesting language ({c} pattern{'s' if c > 1 else ''}, +{pts} points)"
            )

        t = self._count(self.THREAT, text)
        if t:
            pts = min(4, t * 2)
            score += pts
            signals.append(
                f"Threatening consequence language ({t} pattern{'s' if t > 1 else ''}, +{pts} points)"
            )

        s = self._count(self.SOCIAL_ENG, text)
        if s:
            pts = min(3, s)
            score += pts
            signals.append(
                f"Social engineering patterns ({s} pattern{'s' if s > 1 else ''}, +{pts} points)"
            )

        if re.search(r'urgent|action required|immediately', subject, re.IGNORECASE):
            score += 2
            signals.append("Subject line contains urgency indicators (+2 points)")

        return {
            "signals": signals,
            "score_contribution": min(25, score),
            "model_used": "rule-based-classifier-v1",
            "is_rule_based": True,
        }


_classifier: ModelInterface = RuleBasedClassifier()


def _token_chunks(
    subject_ids: list[int],
    body_ids: list[int],
    max_tokens: int,
    overlap: int,
) -> list[list[int]]:
    subject_budget = min(len(subject_ids), max(0, max_tokens // 4))
    prefix = subject_ids[:subject_budget]
    body_budget = max_tokens - len(prefix)
    if body_budget <= 0:
        return [prefix[:max_tokens]]
    if not body_ids:
        return [prefix]

    stride = max(1, body_budget - min(overlap, body_budget - 1))
    chunks = []
    for start in range(0, len(body_ids), stride):
        chunks.append(prefix + body_ids[start:start + body_budget])
        if start + body_budget >= len(body_ids):
            break
    return chunks


class TransformerRunner:
    def __init__(self, model_id: str, model: Any, tokenizer: Any, torch: Any, device: str):
        self.model_id = model_id
        self.model = model
        self.tokenizer = tokenizer
        self.torch = torch
        self.device = device
        config_labels = getattr(model.config, "id2label", {}) or {}
        self.labels = [
            str(config_labels.get(index, config_labels.get(str(index), f"LABEL_{index}")))
            for index in range(model.config.num_labels)
        ]
        configured_map = (
            settings.ai_bert_label_map
            if model_id == settings.ai_bert_model_id
            else settings.ai_roberta_label_map
            if model_id == settings.ai_roberta_model_id
            else {}
        )
        self.class_mapping = {
            raw_label: configured_map.get(
                raw_label,
                "phishing" if re.fullmatch(
                    r"phish(?:ing)?", raw_label.strip(), re.IGNORECASE
                ) else "benign" if re.fullmatch(
                    r"benign|ham|legitimate", raw_label.strip(), re.IGNORECASE
                ) else "",
            )
            if configured_map.get(raw_label, "").strip().casefold() in ("", "benign", "phishing")
            else ""
            for raw_label in self.labels
        }
        self.phishing_index = next(
            (index for index, label in enumerate(self.labels)
             if self.class_mapping[label] == "phishing"),
            None,
        )
        self.benign_index = next(
            (index for index, label in enumerate(self.labels)
             if self.class_mapping[label] == "benign"),
            None,
        )

    def _encode_text(self, text: str) -> list[int]:
        backend = getattr(self.tokenizer, "backend_tokenizer", None)
        if backend is not None:
            return backend.encode(text, add_special_tokens=False).ids
        return self.tokenizer.convert_tokens_to_ids(self.tokenizer.tokenize(text))

    def predict(self, subject: str, body: str) -> dict:
        max_length = max(8, int(settings.ai_max_sequence_length))
        position_limit = getattr(self.model.config, "max_position_embeddings", max_length)
        max_length = min(max_length, int(position_limit))
        special_tokens = self.tokenizer.num_special_tokens_to_add(pair=False)
        content_limit = max(1, max_length - special_tokens)
        subject_ids = self._encode_text(subject or "")
        body_text = f" {body}" if subject_ids and body else body or ""
        body_ids = self._encode_text(body_text)
        chunks = _token_chunks(subject_ids, body_ids, content_limit, content_limit // 5)
        probabilities = []
        pad_token_id = self.tokenizer.pad_token_id
        if pad_token_id is None:
            raise RuntimeError(f"Tokenizer for {self.model_id} has no padding token.")

        self.model.eval()
        with self.torch.inference_mode():
            for start in range(0, len(chunks), max(1, settings.ai_batch_size)):
                batch_chunks = chunks[start:start + max(1, settings.ai_batch_size)]
                encoded = [
                    self.tokenizer.build_inputs_with_special_tokens(chunk)
                    for chunk in batch_chunks
                ]
                batch_length = max(len(item) for item in encoded)
                input_rows = []
                attention_rows = []
                for item in encoded:
                    padding = batch_length - len(item)
                    if getattr(self.tokenizer, "padding_side", "right") == "left":
                        input_rows.append([pad_token_id] * padding + item)
                        attention_rows.append([0] * padding + [1] * len(item))
                    else:
                        input_rows.append(item + [pad_token_id] * padding)
                        attention_rows.append([1] * len(item) + [0] * padding)
                input_ids = self.torch.tensor(input_rows, dtype=self.torch.long, device=self.device)
                attention_mask = self.torch.tensor(
                    attention_rows, dtype=self.torch.long, device=self.device
                )
                logits = self.model(input_ids=input_ids, attention_mask=attention_mask).logits
                probabilities.extend(self.torch.softmax(logits, dim=-1).cpu().tolist())

        if not probabilities:
            raise RuntimeError("The tokenizer produced no model input chunks.")
        averaged = [
            sum(row[index] for row in probabilities) / len(probabilities)
            for index in range(len(self.labels))
        ]
        predicted_index = max(range(len(averaged)), key=averaged.__getitem__)
        benign_probability = (
            averaged[self.benign_index] if self.benign_index is not None else None
        )
        phishing_probability = (
            averaged[self.phishing_index]
            if self.phishing_index is not None else None
        )
        return {
            "model_id": self.model_id,
            "status": "AVAILABLE",
            "labels": [
                {
                    "label": label,
                    "normalized_label": self.class_mapping[label] or None,
                    "probability": averaged[index],
                }
                for index, label in enumerate(self.labels)
            ],
            "predicted_label": self.labels[predicted_index],
            "predicted_class": self.class_mapping[self.labels[predicted_index]] or None,
            "class_mapping": self.class_mapping,
            "benign_probability": benign_probability,
            "phishing_probability": phishing_probability,
            "chunks": len(chunks),
            "aggregation": "Arithmetic mean of per-chunk class probabilities",
        }


class AIAnalysisService:
    def __init__(self):
        self.runners: dict[str, TransformerRunner] = {}
        self.model_states: dict[str, dict] = {}

    def load_models(self) -> None:
        self.runners.clear()
        self.model_states.clear()
        if not settings.ai_models_enabled:
            self.model_states = {
                "BERT": {"model_id": settings.ai_bert_model_id, "status": "DISABLED"},
                "RoBERTa": {"model_id": settings.ai_roberta_model_id, "status": "DISABLED"},
            }
            return

        model_ids = {
            "BERT": settings.ai_bert_model_id,
            "RoBERTa": settings.ai_roberta_model_id,
        }
        for name, model_id in model_ids.items():
            try:
                import torch
                from transformers import AutoModelForSequenceClassification, AutoTokenizer

                device = settings.ai_device
                if device == "auto":
                    device = "cuda" if torch.cuda.is_available() else "cpu"
                tokenizer = AutoTokenizer.from_pretrained(model_id)
                model = AutoModelForSequenceClassification.from_pretrained(model_id)
                model.to(device)
                self.runners[name] = TransformerRunner(model_id, model, tokenizer, torch, device)
                self.model_states[name] = {"model_id": model_id, "status": "AVAILABLE"}
            except Exception as exc:
                logger.exception("Unable to load optional %s model %s", name, model_id)
                self.model_states[name] = {
                    "model_id": model_id,
                    "status": "UNAVAILABLE",
                    "error": str(exc),
                }

    def analyze(self, subject: str, body: str) -> dict:
        input_limit = max(1, settings.ai_max_input_characters)
        analyzed_subject = (subject or "")[:min(1000, input_limit)]
        body_limit = max(0, input_limit - len(analyzed_subject))
        analyzed_body = (body or "")[:body_limit]
        input_truncated = (
            len(subject or "") > len(analyzed_subject)
            or len(body or "") > len(analyzed_body)
        )
        results = []
        for name in ("BERT", "RoBERTa"):
            state = self.model_states.get(name, {
                "model_id": (
                    settings.ai_bert_model_id if name == "BERT"
                    else settings.ai_roberta_model_id
                ),
                "status": "NOT_INITIALIZED",
            })
            runner = self.runners.get(name)
            if runner is None:
                results.append({"name": name, **state})
                continue
            try:
                results.append({
                    "name": name,
                    **runner.predict(analyzed_subject, analyzed_body),
                })
            except Exception as exc:
                logger.exception("Unable to analyze email with %s model", name)
                results.append({
                    "name": name,
                    "model_id": runner.model_id,
                    "status": "UNAVAILABLE",
                    "error": str(exc),
                })

        paired_probabilities = [
            (result["benign_probability"], result["phishing_probability"])
            for result in results
            if result.get("status") == "AVAILABLE"
            and result.get("benign_probability") is not None
            and result.get("phishing_probability") is not None
        ]
        aggregate = (
            sum(probabilities[1] for probabilities in paired_probabilities)
            / len(paired_probabilities)
            if paired_probabilities else None
        )
        aggregate_benign = 1 - aggregate if aggregate is not None else None
        threshold = min(1.0, max(0.0, settings.ai_phishing_threshold))
        weight = min(25, max(0, settings.ai_risk_weight))
        contribution = (
            round(weight * (aggregate - threshold) / (1.0 - threshold))
            if aggregate is not None and aggregate > threshold and threshold < 1.0
            else 0
        )
        statuses = {result.get("status") for result in results}
        status = (
            "AVAILABLE" if statuses == {"AVAILABLE"}
            else "PARTIAL" if "AVAILABLE" in statuses
            else "DISABLED" if statuses == {"DISABLED"}
            else "UNAVAILABLE"
        )
        return {
            "status": status,
            "models": results,
            "aggregate_phishing_probability": (
                aggregate
            ),
            "aggregate_benign_probability": aggregate_benign,
            "combined_ai_signal": {
                "benign_probability": aggregate_benign,
                "phishing_probability": aggregate,
                "models_used": len(paired_probabilities),
                "aggregation": "Arithmetic mean of normalized available model probabilities",
            },
            "risk_contribution": min(weight, max(0, contribution)),
            "risk_weight": weight,
            "phishing_threshold": threshold,
            "input_truncated": input_truncated,
            "input_characters": (
                len(analyzed_subject)
                + len(analyzed_body)
                + int(bool(analyzed_subject and analyzed_body))
            ),
        }


_ai_analysis_service = AIAnalysisService()


def analyze_content(subject: str, body: str) -> dict:
    rule_result = _classifier.analyze(subject, body)
    ai_analysis = _ai_analysis_service.analyze(subject, body)
    rule_score = rule_result["score_contribution"]
    ai_score = min(ai_analysis["risk_contribution"], 25 - rule_score)
    ai_analysis["risk_contribution"] = ai_score
    ai_probability = ai_analysis.get("aggregate_phishing_probability")
    ai_threshold = ai_analysis.get("phishing_threshold")
    ai_weight = ai_analysis.get("risk_weight", 0)
    ai_explanation = []
    if (
        isinstance(ai_probability, (int, float))
        and isinstance(ai_threshold, (int, float))
        and ai_probability > ai_threshold
        and ai_threshold < 1
        and ai_weight > 0
    ):
        raw_points = ai_weight * (ai_probability - ai_threshold) / (1 - ai_threshold)
        if ai_score == 0:
            if rule_score >= 25:
                ai_explanation.append(
                    f"AI phishing probability {ai_probability:.2%} exceeded the "
                    f"{ai_threshold:.2%} threshold, but the 25-point content "
                    "cap was already reached by deterministic rules."
                )
            else:
                ai_explanation.append(
                    f"AI phishing probability {ai_probability:.2%} exceeded the "
                    f"{ai_threshold:.2%} threshold; {raw_points:.2f}/{ai_weight} "
                    "raw point(s) rounded to 0 integer points."
                )
    return {
        **rule_result,
        "signals": [
            *rule_result["signals"],
            *ai_explanation,
            *(
                [f"Transformer phishing analysis contributed {ai_score} risk point(s)"]
                if ai_score else []
            ),
        ],
        "score_contribution": rule_score + ai_score,
        "rule_score": rule_score,
        "ai_score": ai_score,
        "ai_analysis": ai_analysis,
    }
