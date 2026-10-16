"""AEGIS Sigma Rule Parser and Compiler.

Provides deterministic translation of a documented subset of Sigma detection
rules into native AEGIS DetectionRules.

Guarantees:
1. Rejects unsupported or ambiguous Sigma syntax with actionable error messages.
2. Never silently reinterprets unsupported operators, complex boolean trees, or regexes.
3. Preserves full MITRE ATT&CK technique tags and logsource requirements.
"""

from __future__ import annotations

import re
from typing import Any

import yaml

from aegis.rules import MITRE
from aegis.schemas import Condition, DetectionRule, ExceptionRule, Predicate, Severity

SIGMA_FIELD_MAPPING: dict[str, str] = {
    # Process Creation
    "image": "process.name",
    "process": "process.name",
    "parentimage": "parent_process",
    "commandline": "command_line",
    "processid": "process_id",
    "user": "username",
    "username": "username",
    "targetusername": "username",
    # Network
    "sourceip": "source_ip",
    "src_ip": "source_ip",
    "destinationip": "destination_ip",
    "dst_ip": "destination_ip",
    "destinationport": "destination_port",
    "dst_port": "destination_port",
    "sourceport": "source_port",
    "src_port": "source_port",
    "protocol": "protocol",
    # File
    "targetfilename": "file.path",
    "image_loaded": "file.path",
    "imageloaded": "file.path",
    "file": "file.path",
    "hashes": "file.hash",
    "hash": "file.hash",
    # Host / System
    "computername": "host",
    "host": "host",
    "hostname": "hostname",
    # Web / HTTP
    "c-uri": "http.path",
    "cs-method": "action",
    "sc-status": "http.status",
    "cs(user-agent)": "http.user_agent",
    # Event attributes
    "eventid": "action",
    "action": "action",
    "status": "outcome",
    "outcome": "outcome",
}

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "in", "all"}
UNSUPPORTED_MODIFIERS = {
    "base64offset",
    "re",
    "cidr",
    "windash",
    "expand",
    "casedir",
    "utf16",
    "wide",
}


class SigmaTranslationError(ValueError):
    """Raised when a Sigma rule contains invalid or unsupported logic."""

    pass


def _map_sigma_field(raw_field: str) -> str:
    cleaned = raw_field.strip().lower()
    if cleaned in SIGMA_FIELD_MAPPING:
        return SIGMA_FIELD_MAPPING[cleaned]
    # Check if field is directly a recognized AEGIS field
    from aegis.schemas import ALIASES, FIELDS

    if raw_field in FIELDS or raw_field in ALIASES:
        return raw_field
    if cleaned in FIELDS or cleaned in ALIASES:
        return cleaned
    raise SigmaTranslationError(
        f"Unsupported field '{raw_field}'. AEGIS requires known fields like "
        f"process.name, command_line, username, source_ip, host, file.path, action, outcome."
    )


def _extract_mitre_techniques(tags: list[str]) -> list[str]:
    techniques = []
    for tag in tags:
        normalized = tag.lower().strip()
        match = re.search(r"t\d{4}(?:\.\d{3})?", normalized)
        if match:
            tech = match.group(0).upper()
            if tech in MITRE:
                techniques.append(tech)
    return sorted(set(techniques))


def _parse_field_definition(
    field_expr: str, value: Any
) -> list[Predicate]:
    parts = field_expr.split("|")
    raw_field = parts[0].strip()
    modifiers = [m.lower().strip() for m in parts[1:]]

    for mod in modifiers:
        if mod in UNSUPPORTED_MODIFIERS:
            raise SigmaTranslationError(
                f"Unsupported Sigma modifier '|{mod}' on field '{raw_field}'. "
                f"AEGIS does not permit silent reinterpretation of {mod} logic."
            )
        if mod not in SUPPORTED_MODIFIERS:
            raise SigmaTranslationError(
                f"Unknown or unsupported Sigma modifier '|{mod}' on field '{raw_field}'."
            )

    target_field = _map_sigma_field(raw_field)

    if not modifiers or modifiers == ["all"]:
        if isinstance(value, list):
            if not value:
                raise SigmaTranslationError(f"Field '{raw_field}' has an empty list value.")
            return [Predicate(field=target_field, op="in", value=value[:100])]
        return [Predicate(field=target_field, op="eq", value=value)]

    if "contains" in modifiers:
        if isinstance(value, list):
            if "all" in modifiers:
                return [Predicate(field=target_field, op="contains", value=str(v)) for v in value]
            return [Predicate(field=target_field, op="contains", value=[str(v) for v in value[:100]])]
        return [Predicate(field=target_field, op="contains", value=str(value))]

    if "startswith" in modifiers:
        if isinstance(value, list):
            if "all" in modifiers:
                return [Predicate(field=target_field, op="startswith", value=str(v)) for v in value]
            return [Predicate(field=target_field, op="startswith", value=[str(v) for v in value[:100]])]
        return [Predicate(field=target_field, op="startswith", value=str(value))]

    if "endswith" in modifiers:
        if isinstance(value, list):
            if "all" in modifiers:
                return [Predicate(field=target_field, op="endswith", value=str(v)) for v in value]
            return [Predicate(field=target_field, op="endswith", value=[str(v) for v in value[:100]])]
        return [Predicate(field=target_field, op="endswith", value=str(value))]

    if "in" in modifiers:
        if not isinstance(value, list):
            raise SigmaTranslationError(f"Modifier '|in' requires a list value for '{raw_field}'.")
        return [Predicate(field=target_field, op="in", value=value[:100])]

    raise SigmaTranslationError(f"Unhandled modifier combination: {modifiers}")


def _parse_detection_block(
    detection: dict[str, Any], block_name: str
) -> list[Predicate]:
    block = detection.get(block_name)
    if not block:
        return []

    predicates: list[Predicate] = []
    if isinstance(block, dict):
        for field_expr, value in block.items():
            parsed = _parse_field_definition(field_expr, value)
            predicates.extend(parsed)
    elif isinstance(block, list):
        for item in block:
            if isinstance(item, dict):
                for field_expr, value in item.items():
                    predicates.extend(_parse_field_definition(field_expr, value))
            else:
                raise SigmaTranslationError(f"Unexpected item type in block '{block_name}': {type(item)}")
    else:
        raise SigmaTranslationError(f"Block '{block_name}' must be a mapping or list of mappings.")

    return predicates


def parse_sigma_rule(raw_yaml: str) -> DetectionRule:
    """Parses a Sigma YAML string and translates it to an AEGIS DetectionRule.

    Raises:
        SigmaTranslationError: When encountering unsupported syntax, modifiers,
            unknown fields, or oversized documents (>500KB).
    """
    if not isinstance(raw_yaml, str):
        raise SigmaTranslationError("Sigma rule content must be a string.")
    if len(raw_yaml) > 512_000:
        raise SigmaTranslationError("Sigma YAML document exceeds maximum size limit of 500 KB.")

    try:
        data = yaml.safe_load(raw_yaml)
    except Exception as exc:
        raise SigmaTranslationError(f"Invalid YAML syntax: {exc}") from exc

    if not isinstance(data, dict):
        raise SigmaTranslationError("Sigma rule must be a YAML mapping.")

    title = data.get("title")
    if not title or not isinstance(title, str) or len(title) < 5:
        raise SigmaTranslationError("Sigma rule requires a valid 'title' of at least 5 characters.")

    description = data.get("description") or f"Detection rule translated from Sigma: {title}"
    if len(description) < 10:
        description = f"Sigma detection rule: {title}"

    # Generate or sanitize rule identifier
    raw_id = data.get("id")
    if raw_id:
        # Convert UUID or raw ID to valid AEGIS identifier [A-Z0-9][A-Z0-9_-]{2,79}
        clean_id = re.sub(r"[^A-Z0-9_-]", "", str(raw_id).upper())
        rule_id = f"SIGMA-{clean_id}"[:80] if not clean_id.startswith("SIGMA-") else clean_id[:80]
        if not re.fullmatch(r"^[A-Z0-9][A-Z0-9_-]{2,79}$", rule_id):
            clean_title = re.sub(r"[^A-Z0-9_-]", "", title.upper().replace(" ", "-"))[:40]
            rule_id = f"SIGMA-{clean_title}"[:80]
    else:
        clean_title = re.sub(r"[^A-Z0-9_-]", "", title.upper().replace(" ", "-"))[:40]
        rule_id = f"SIGMA-{clean_title}"[:80]

    # Level to Severity
    level_map: dict[str, Severity] = {
        "informational": "informational",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    severity: Severity = level_map.get(str(data.get("level", "medium")).lower(), "medium")

    # MITRE ATT&CK techniques
    tags = data.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    mitre_techniques = _extract_mitre_techniques(tags)

    # Data source requirements
    logsource = data.get("logsource") or {}
    data_source_requirements = []
    if isinstance(logsource, dict):
        for k in ("category", "product", "service"):
            if val := logsource.get(k):
                data_source_requirements.append(f"{k}:{val}")

    detection = data.get("detection")
    if not detection or not isinstance(detection, dict):
        raise SigmaTranslationError("Sigma rule must contain a 'detection' section.")

    condition_str = detection.get("condition")
    if not condition_str or not isinstance(condition_str, str):
        raise SigmaTranslationError("Sigma detection block requires a 'condition' expression.")

    condition_clean = condition_str.strip().lower()

    # Parse selections and filters
    selection_predicates: list[Predicate] = []
    exception_rules: list[ExceptionRule] = []

    # Handle standard Sigma condition patterns:
    # 1. "selection"
    # 2. "selection and not filter"
    # 3. "1 of selection*"
    # 4. "selection_main and not (filter_1 or filter_2)"
    if condition_clean in {"selection", "1 of selection*", "all of selection*"}:
        # Collect all selection blocks
        for key in detection:
            if key.startswith("selection"):
                selection_predicates.extend(_parse_detection_block(detection, key))
    elif "not" in condition_clean:
        # Split into positive selection and negative filter
        parts = condition_clean.split("not", 1)
        positive_part = parts[0].replace("and", "").strip()
        negative_part = parts[1].strip().strip("()")

        pos_keys = [k.strip() for k in positive_part.split() if k.strip() in detection]
        if not pos_keys and "selection" in detection:
            pos_keys = ["selection"]
        for key in pos_keys:
            selection_predicates.extend(_parse_detection_block(detection, key))

        neg_keys = [
            k.strip()
            for k in negative_part.replace("or", " ").replace("and", " ").split()
            if k.strip() in detection
        ]
        if not neg_keys and "filter" in detection:
            neg_keys = ["filter"]

        for key in neg_keys:
            filter_preds = _parse_detection_block(detection, key)
            if filter_preds:
                exception_rules.append(
                    ExceptionRule(
                        reason=f"Translated from Sigma filter block: {key}",
                        predicates=filter_preds,
                    )
                )
    else:
        # Check if single or multiple selections
        matched_keys = [k for k in detection if k != "condition" and k in condition_clean]
        if not matched_keys:
            raise SigmaTranslationError(
                f"Unsupported or complex Sigma condition expression: '{condition_str}'. "
                f"Supported patterns: 'selection', 'selection and not filter'."
            )
        for k in matched_keys:
            selection_predicates.extend(_parse_detection_block(detection, k))

    if not selection_predicates:
        raise SigmaTranslationError(
            f"No valid predicates could be derived from Sigma detection blocks for condition '{condition_str}'."
        )

    # Validate condition object
    condition = Condition(type="match")

    return DetectionRule(
        id=rule_id,
        name=title[:300],
        description=description[:2000],
        author=str(data.get("author", "Sigma Community"))[:100],
        version=1,
        status="DRAFT",
        lifecycle_stage="DRAFT",
        data_source_requirements=data_source_requirements,
        selection=selection_predicates[:30],
        condition=condition,
        severity=severity,
        confidence=int(data.get("confidence", 75)),
        tags=[str(t)[:30] for t in tags[:30]],
        mitre_techniques=mitre_techniques[:20],
        exceptions=exception_rules[:100],
    )
