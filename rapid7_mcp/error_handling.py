"""Human-friendly error parser and plain-language mapper for Rapid7 and connector errors.

Ensures that raw HTTP JSON bodies, Spring framework class names, and stack traces
never leak into user-facing assistant answers.
"""

import json
import logging
import re
from typing import Any

logger = logging.getLogger("pebbles.errors")


def map_rapid7_error_to_human(status_code: int, raw_error: str) -> str:
    """Map a raw Rapid7 HTTP error string/JSON into clean, plain-language text."""
    clean_text = raw_error.strip()

    # Attempt to extract error message from Spring JSON if present
    extracted_msg = ""
    try:
        # Check if the string contains a JSON object
        json_match = re.search(r"\{.*\}", clean_text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(0))
            if isinstance(data, dict):
                extracted_msg = data.get("message") or data.get("error") or data.get("localizedMessage") or ""
    except Exception:
        pass

    if not extracted_msg:
        # Strip JSON-like artifacts if parsing failed
        clean_no_json = re.sub(r'\{[^}]+\}', '', clean_text).strip()
        extracted_msg = clean_no_json if clean_no_json else clean_text

    # Strip Java stack traces or Spring class names if present
    extracted_msg = re.sub(r'com\.rapid7\.[a-zA-Z0-9_\.]+', '', extracted_msg).strip()

    if status_code == 400:
        if "leql" in extracted_msg.lower() or "query" in extracted_msg.lower():
            return f"The search query wasn't understood by Rapid7 Log Search. Details: {extracted_msg if extracted_msg else 'Invalid syntax'}."
        return f"Rapid7 couldn't process this request because of an invalid query parameter ({extracted_msg if extracted_msg else 'Bad Request'})."

    elif status_code == 401:
        if "insightvm" in extracted_msg.lower():
            return (
                "The connected API key lacks InsightVM vulnerability permissions. "
                "An Organization API Key or a key with an InsightVM Administrator role is required."
            )
        return "The Rapid7 API key was rejected or has expired. Please check your key in the sidebar."

    elif status_code == 403:
        return "Your connected Rapid7 key doesn't have permission to view this specific resource."

    elif status_code == 404:
        return "The requested investigation, asset, or log resource could not be found in Rapid7."

    elif status_code == 429:
        return "Rapid7 rate limit reached (HTTP 429). Please pause for a moment before searching again."

    elif status_code in (500, 502, 503, 504):
        return "Rapid7 platform services returned a server error. Please try again shortly."

    return f"Rapid7 returned HTTP {status_code}: {extracted_msg if extracted_msg else 'An unexpected error occurred'}."
