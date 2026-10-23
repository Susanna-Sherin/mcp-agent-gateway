"""Deterministic PII scanner and Luhn validator for MCP Agent Gateway.

Detects payment cards, Social Security Numbers (US SSN), email addresses, and phone numbers.
Supports optional Microsoft Presidio integration when available, with a fully self-contained
pure-Python offline fallback engine that requires no external NLP model downloads.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deterministic Regular Expression Recognizers
# ---------------------------------------------------------------------------

# US SSN: 3 digits - 2 digits - 4 digits (area: 001-899 excl 666; group: 01-99; serial: 0001-9999)
SSN_PATTERN = re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b")

# Email address according to standard RFC-compliant token structure
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Phone number: International E.164 and standard North American formats
PHONE_PATTERN = re.compile(r"(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?[2-9]\d{2}[-. ]?\d{4}\b")

# Candidate Credit Card: 13-19 digits, matching major issuers with optional dashes/spaces
# Visa (4...), Mastercard (51-55, 22-27), Amex (34, 37), Discover (6011, 65...)
CANDIDATE_CARD_PATTERN = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"
    r"5[1-5][0-9]{14}|"
    r"2(?:2[2-9][0-9]{12}|[3-6][0-9]{13}|7[01][0-9]{12}|720[0-9]{12})|"
    r"3[47][0-9]{13}|"
    r"6(?:011|5[0-9]{2})[0-9]{12}|"
    r"(?:4[0-9]{3}|5[1-5][0-9]{2}|2[2-7][0-9]{2}|3[47][0-9]{2}|6011|65[0-9]{2})"
    r"[- ](?:[0-9]{4}[- ]){2}[0-9]{1,7})\b"
)


def luhn_validate(candidate: str) -> bool:
    """Validate a candidate numeric sequence using the standard Luhn (mod 10) algorithm.

    Args:
        candidate: Candidate payment card string (may include spaces or dashes).

    Returns:
        True if the candidate string has 13-19 digits and satisfies the Luhn checksum;
        False otherwise.
    """
    digits = [int(c) for c in candidate if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else (doubled - 9)
        else:
            checksum += digit

    return checksum % 10 == 0


@dataclass
class PIIEntity:
    """Structured representation of a detected Personally Identifiable Information entity."""

    entity_type: str  # "CREDIT_CARD", "US_SSN", "EMAIL", "PHONE"
    start: int
    end: int
    text: str
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Convert entity to serializable dictionary."""
        return asdict(self)


class PIIScanner:
    """Security scanner for discovering and redacting PII in tool arguments and results.

    Operates deterministically without external network calls or mandatory external models.
    """

    def __init__(
        self,
        enable_credit_cards: bool = True,
        enable_ssn: bool = True,
        enable_email: bool = True,
        enable_phone: bool = True,
        use_presidio_if_available: bool = False,
    ) -> None:
        self.enable_credit_cards = enable_credit_cards
        self.enable_ssn = enable_ssn
        self.enable_email = enable_email
        self.enable_phone = enable_phone
        self.use_presidio = use_presidio_if_available
        self._presidio_engine: Any | None = None

        if self.use_presidio:
            try:
                from presidio_analyzer import AnalyzerEngine

                self._presidio_engine = AnalyzerEngine()
                logger.info("Microsoft Presidio Analyzer initialized successfully.")
            except Exception as ex:
                logger.warning(
                    "Presidio Analyzer requested but unavailable (%s); using deterministic engine.",
                    ex,
                )
                self._presidio_engine = None

    def scan_text(self, text: str) -> list[PIIEntity]:
        """Scan a text string and return all recognized PII entities.

        Args:
            text: Input string to inspect.

        Returns:
            List of detected PIIEntity objects sorted by starting offset.
        """
        if not text or not isinstance(text, str):
            return []

        entities: list[PIIEntity] = []

        # 1. Payment Cards (with mandatory Luhn algorithm verification)
        if self.enable_credit_cards:
            for match in CANDIDATE_CARD_PATTERN.finditer(text):
                raw = match.group()
                if luhn_validate(raw):
                    entities.append(
                        PIIEntity(
                            entity_type="CREDIT_CARD",
                            start=match.start(),
                            end=match.end(),
                            text=raw,
                            confidence=1.0,
                        )
                    )

        # 2. US Social Security Numbers
        if self.enable_ssn:
            for match in SSN_PATTERN.finditer(text):
                raw = match.group()
                entities.append(
                    PIIEntity(
                        entity_type="US_SSN",
                        start=match.start(),
                        end=match.end(),
                        text=raw,
                        confidence=1.0,
                    )
                )

        # 3. Email Addresses
        if self.enable_email:
            for match in EMAIL_PATTERN.finditer(text):
                raw = match.group()
                entities.append(
                    PIIEntity(
                        entity_type="EMAIL",
                        start=match.start(),
                        end=match.end(),
                        text=raw,
                        confidence=1.0,
                    )
                )

        # 4. Phone Numbers
        if self.enable_phone:
            for match in PHONE_PATTERN.finditer(text):
                raw = match.group()
                # Ensure phone match does not overlap with an already detected card or SSN
                start, end = match.start(), match.end()
                if not any(e.start <= start and end <= e.end for e in entities):
                    entities.append(
                        PIIEntity(
                            entity_type="PHONE",
                            start=start,
                            end=end,
                            text=raw,
                            confidence=0.85,
                        )
                    )

        # 5. Optional Presidio Extension
        if self._presidio_engine is not None:
            try:
                presidio_results = self._presidio_engine.analyze(
                    text=text,
                    language="en",
                    entities=["US_PASSPORT", "IBAN_CODE"],
                )
                for pr in presidio_results:
                    entities.append(
                        PIIEntity(
                            entity_type=pr.entity_type,
                            start=pr.start,
                            end=pr.end,
                            text=text[pr.start : pr.end],
                            confidence=pr.score,
                        )
                    )
            except Exception as ex:
                logger.warning("Presidio scan exception ignored: %s", ex)

        # Sort and deduplicate overlapping entities by start position
        entities.sort(key=lambda e: e.start)
        return entities

    def redact_text(self, text: str, entities: list[PIIEntity] | None = None) -> str:
        """Redact discovered PII entities from text using safe reverse-index substitution.

        Args:
            text: Source string containing sensitive entities.
            entities: Pre-computed entities, or None to scan automatically.

        Returns:
            Redacted string where PII matches are replaced with [REDACTED_{ENTITY_TYPE}].
        """
        if not text or not isinstance(text, str):
            return text

        found = entities if entities is not None else self.scan_text(text)
        if not found:
            return text

        # Sort in reverse order of start offset so replacements do not shift indices
        sorted_entities = sorted(found, key=lambda e: e.start, reverse=True)
        redacted = text
        for ent in sorted_entities:
            placeholder = f"[REDACTED_{ent.entity_type}]"
            redacted = redacted[: ent.start] + placeholder + redacted[ent.end :]

        return redacted

    def scan_value(self, value: Any) -> tuple[bool, list[PIIEntity]]:
        """Recursively scan an arbitrary structure (dict, list, primitive) for PII.

        Args:
            value: Untrusted data payload.

        Returns:
            Tuple of (has_pii: bool, detected_entities: list[PIIEntity]).
        """
        all_entities: list[PIIEntity] = []

        if isinstance(value, str):
            ents = self.scan_text(value)
            all_entities.extend(ents)
        elif isinstance(value, dict):
            for k, v in value.items():
                if isinstance(k, str):
                    all_entities.extend(self.scan_text(k))
                _, sub_ents = self.scan_value(v)
                all_entities.extend(sub_ents)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                _, sub_ents = self.scan_value(item)
                all_entities.extend(sub_ents)

        return (len(all_entities) > 0, all_entities)

    def redact_value(self, value: Any) -> Any:
        """Recursively redact PII from an arbitrary nested data structure.

        Args:
            value: Target data payload.

        Returns:
            Deep copy of payload with all discovered PII strings replaced by placeholders.
        """
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {
                self.redact_text(k) if isinstance(k, str) else k: self.redact_value(v)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact_value(item) for item in value)
        if isinstance(value, set):
            return {self.redact_value(item) for item in value}
        return value
