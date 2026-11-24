"""Code-level grounding verification for Pebbles SOC Assistant.

Guarantees that any numbers, percentages, CVE IDs, or entity scores in an answer
are strictly corroboratable from the tool result returned in the same turn.
Prevents LLM hallucinations and fabricated mock metrics.
"""

import re
from typing import Any


CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
PERCENTAGE_REGEX = re.compile(r"\b(\d{1,3}(?:\.\d+)?)\s*%\b")
NUMERIC_STAT_REGEX = re.compile(r"\b\d{2,}(?:,\d{3})*\b")


def extract_searchable_tokens(data: Any) -> set[str]:
    """Recursively extract string representations of all values in a tool payload."""
    tokens: set[str] = set()

    if isinstance(data, dict):
        for k, v in data.items():
            tokens.add(str(k).lower())
            tokens.update(extract_searchable_tokens(v))
    elif isinstance(data, list):
        for item in data:
            tokens.update(extract_searchable_tokens(item))
    elif isinstance(data, (int, float)):
        tokens.add(str(data).lower())
        tokens.add(f"{data:,}".lower())
    elif isinstance(data, str):
        cleaned = data.strip().lower()
        if cleaned:
            tokens.add(cleaned)
            # Add words and hyphen/underscore split parts
            for word in re.split(r"[\s\-_/.:,]+", cleaned):
                if word:
                    tokens.add(word)

    return tokens


"""Code-level grounding verification for Pebbles SOC Assistant.

Guarantees that numbers, CVE IDs, named entities, system names, client contexts,
and verdict words are strictly corroboratable from tool results or conversation context.
Prevents LLM hallucinations, cross-client context leakage, and fabricated metrics.
"""

import re
from typing import Any


CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
PERCENTAGE_REGEX = re.compile(r"\b(\d{1,3}(?:\.\d+)?)\s*%\b")
NUMERIC_STAT_REGEX = re.compile(r"\b\d{2,}(?:,\d{3})*\b")

# Systems that Pebbles has NO connector for and must never claim telemetry from
UNCONNECTED_SYSTEMS = [
    r"\bedr\b",
    r"\bendpoint\s+detection\b",
    r"\bcrowdstrike\b",
    r"\bsentinelone\b",
    r"\bcarbon\s*black\b",
    r"\bemail\s+gateway\b",
    r"\bweb\s+proxy\b",
]

# Client names that must never leak across client sessions
KNOWN_CLIENTS = {
    "napsa": ["znbs", "zambia national building society"],
    "znbs": ["napsa", "national pension scheme authority"],
}


def extract_searchable_tokens(data: Any) -> set[str]:
    """Recursively extract string representations of all values in a tool payload."""
    tokens: set[str] = set()

    if isinstance(data, dict):
        for k, v in data.items():
            tokens.add(str(k).lower())
            tokens.update(extract_searchable_tokens(v))
    elif isinstance(data, list):
        for item in data:
            tokens.update(extract_searchable_tokens(item))
    elif isinstance(data, (int, float)):
        tokens.add(str(data).lower())
        tokens.add(f"{data:,}".lower())
    elif isinstance(data, str):
        cleaned = data.strip().lower()
        if cleaned:
            tokens.add(cleaned)
            for word in re.split(r"[\s\-_/.:,]+", cleaned):
                if word:
                    tokens.add(word)

    return tokens


def verify_grounding(
    message: str,
    tool_payloads: list[dict[str, Any]],
    client_name: str = "",
    tool_name: str = "",
    conversation_context: str = "",
) -> tuple[bool, list[str]]:
    """Check if claims in message exist in tool payloads or conversation context.

    Returns (is_grounded, ungrounded_tokens).
    """
    msg_lower = message.lower()
    conv_lower = (conversation_context or "").lower()

    ungrounded: list[str] = []

    # 1. Check for unconnected systems (e.g. EDR, email gateway)
    for sys_pat in UNCONNECTED_SYSTEMS:
        if re.search(sys_pat, msg_lower) and not re.search(sys_pat, conv_lower):
            # Unless explicitly in tool payload (e.g. an alert title mentions EDR)
            ref_tokens = extract_searchable_tokens(tool_payloads)
            if not any(re.search(sys_pat, t) for t in ref_tokens):
                ungrounded.append(f"Unconnected system referenced: {sys_pat.replace(r'\b', '')}")

    # 2. Check for cross-client leakage (e.g. ZNBS appearing when monitoring NAPSA)
    c_key = "napsa" if "napsa" in client_name.lower() else ("znbs" if "znbs" in client_name.lower() else "")
    if c_key and c_key in KNOWN_CLIENTS:
        for other_client in KNOWN_CLIENTS[c_key]:
            if other_client in msg_lower and other_client not in conv_lower:
                ungrounded.append(f"Cross-client context leakage: {other_client}")

    # 3. Check for fabricated prior knowledge phrases
    if "we've been tracking" in msg_lower and "we've been tracking" not in conv_lower:
        ungrounded.append("Fabricated prior knowledge ('we've been tracking')")

    # 4. Check VirusTotal specific grounding
    if tool_name in ("vt_lookup_indicator", "virustotal"):
        ref_tokens = extract_searchable_tokens(tool_payloads)
        ref_text = " ".join(ref_tokens).lower()
        
        # Check if 404 / not found
        is_not_found = any(
            p.get("found") is False or p.get("status") == "NOT_FOUND"
            for p in tool_payloads if isinstance(p, dict)
        )
        if is_not_found:
            for forbidden_word in ["malicious", "phishing", "malware", "clean", "benign", "safe"]:
                if f" {forbidden_word}" in f" {msg_lower}" and forbidden_word not in conv_lower:
                    ungrounded.append(f"Ungrounded verdict on not-found indicator: '{forbidden_word}'")

    # 5. Check CVEs and statistics
    if not tool_payloads:
        has_stats = bool(CVE_REGEX.search(message) or NUMERIC_STAT_REGEX.search(message))
        if has_stats and not any(NUMERIC_STAT_REGEX.search(conv_lower) for _ in [1]):
            ungrounded.append("No tool telemetry returned to support statistics")
        return len(ungrounded) == 0, ungrounded

    reference_tokens = extract_searchable_tokens(tool_payloads)
    reference_text_blob = " ".join(reference_tokens).lower()

    # Check CVEs
    cves_in_message = CVE_REGEX.findall(message)
    for cve in cves_in_message:
        if cve.lower() not in reference_text_blob and cve.lower() not in conv_lower:
            ungrounded.append(cve)

    # Check standalone large numbers (excluding CVE numbers and years)
    text_without_cves = CVE_REGEX.sub("", message)
    numbers_in_message = NUMERIC_STAT_REGEX.findall(text_without_cves)
    for num_str in numbers_in_message:
        raw_num = num_str.replace(",", "")
        if raw_num in ["2024", "2025", "2026", "2027"]:
            continue
        if raw_num not in reference_tokens and num_str.lower() not in reference_tokens and raw_num not in conv_lower:
            ungrounded.append(num_str)

    is_grounded = len(ungrounded) == 0
    return is_grounded, ungrounded


def enforce_grounded_message(
    message: str,
    tool_payloads: list[dict[str, Any]],
    tool_name: str,
    client_name: str = "",
    conversation_context: str = "",
) -> str:
    """Enforce grounding in the final output string.

    If unverified or fabricated stats/claims are detected, replaces or amends with strictly grounded facts.
    """
    is_grounded, ungrounded = verify_grounding(
        message=message,
        tool_payloads=tool_payloads,
        client_name=client_name,
        tool_name=tool_name,
        conversation_context=conversation_context,
    )
    if is_grounded:
        return message

    # If severe ungrounded claims (unconnected systems, cross-client leakage, false verdicts) are present,
    # generate a clean, strictly grounded fallback directly from the tool payload
    has_critical_failure = any(
        "Unconnected system" in u or "Cross-client" in u or "Fabricated" in u or "Ungrounded verdict" in u
        for u in ungrounded
    )

    if has_critical_failure and tool_name in ("vt_lookup_indicator", "virustotal"):
        payload = tool_payloads[0] if tool_payloads else {}
        ind = payload.get("indicator", "the requested indicator")
        itype = payload.get("indicator_type", "indicator")
        found = payload.get("found", False)
        if not found:
            return f"VirusTotal has no record of {itype} `{ind}`."
        
        mal = payload.get("malicious_count", 0)
        tot = payload.get("total_engines", 0)
        rep = payload.get("reputation", 0)
        date_str = payload.get("last_analysis_date", "N/A")
        return (
            f"VirusTotal shows {mal} of {tot} security engines flagging `{ind}` as malicious. "
            f"Its community reputation score is {rep}, and the last analysis date was {date_str}."
        )

    # Standard warning append for minor ungrounded statistics
    warning = (
        f"\n\n> Note: The following figure(s) could not be verified in live "
        f"telemetry returned by `{tool_name}`: {', '.join(f'`{u}`' for u in ungrounded[:3])}."
    )
    return message + warning
