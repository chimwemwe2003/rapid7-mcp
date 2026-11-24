"""Gemini LLM Integration for Pebbles SOC Assistant.

Provides conversational intelligence, telemetry synthesis, and multi-turn context
using Google's Gemini models via official REST API with httpx.
Includes anti-repetition guards and sanitization.
"""

import json
import logging
import os
import re
from typing import Any

import httpx

from rapid7_mcp.prompt import PEBBLES_CORE_PRINCIPLES, format_conversation_for_model
from rapid7_mcp.sanitizer import sanitize_markdown_text

logger = logging.getLogger("pebbles.llm")

# Primary and fallback Gemini models
GEMINI_MODELS = [
    "gemini-3.1-flash-lite",
    "gemini-3-flash-preview",
    "gemini-flash-latest",
]

DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"


def _get_gemini_api_key() -> str:
    """Retrieve Gemini API key from environment or .env file."""
    key = os.getenv("GEMINI_API_KEY", "").strip()
    if not key:
        try:
            import dotenv
            dotenv.load_dotenv()
            key = os.getenv("GEMINI_API_KEY", "").strip()
        except Exception:
            pass
    return key


def _get_deepseek_api_key() -> str:
    """Retrieve DeepSeek API key from environment or .env file."""
    key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not key:
        try:
            import dotenv
            dotenv.load_dotenv()
            key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        except Exception:
            pass
    return key


def _format_messages_for_openai(
    system_instruction: str,
    chat_history: list[dict[str, Any]],
    current_query: str,
    telemetry_context: str | None = None,
) -> list[dict[str, str]]:
    """Format messages for OpenAI-compatible APIs (DeepSeek)."""
    messages: list[dict[str, str]] = [{"role": "system", "content": system_instruction}]
    recent_history = chat_history[-8:] if len(chat_history) > 8 else chat_history
    for msg in recent_history:
        role = "user" if msg.get("role") == "user" else "assistant"
        text = msg.get("content") or ""
        if role == "assistant" and len(text) > 500:
            text = text[:500] + "..."
        if text.strip():
            messages.append({"role": role, "content": text.strip()})
    user_turn = current_query
    if telemetry_context:
        user_turn += f"\n\n[Live Security Telemetry]:\n{telemetry_context}"
    messages.append({"role": "user", "content": user_turn})
    return messages


def _post_deepseek(
    api_key: str,
    messages: list[dict[str, str]],
    model: str = DEFAULT_DEEPSEEK_MODEL,
    temperature: float = 0.7,
    max_tokens: int = 650,
    timeout: float = 15.0,
) -> str | None:
    """Execute a chat completion request against the DeepSeek REST API."""
    url = "https://api.deepseek.com/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                choices = data.get("choices") or []
                if choices:
                    msg = choices[0].get("message") or {}
                    content = msg.get("content") or ""
                    if content.strip():
                        return content.strip()
            else:
                logger.warning(f"DeepSeek API returned {resp.status_code}: {resp.text[:120]}")
    except Exception as e:
        logger.warning(f"DeepSeek API request failed: {e}")
    return None


def call_deepseek(
    messages: list[dict[str, str]],
    model: str | None = None,
    temperature: float = 0.7,
    max_tokens: int = 650,
    timeout: float = 15.0,
) -> str | None:
    """Call DeepSeek with configured API key."""
    api_key = _get_deepseek_api_key()
    if not api_key:
        return None
    selected_model = model or os.getenv("DEEPSEEK_MODEL", DEFAULT_DEEPSEEK_MODEL).strip() or DEFAULT_DEEPSEEK_MODEL
    return _post_deepseek(
        api_key=api_key,
        messages=messages,
        model=selected_model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )


def _calculate_similarity(text1: str, text2: str) -> float:
    """Calculate token overlap (Jaccard similarity) between two texts."""
    words1 = set(re.findall(r"\b\w+\b", text1.lower()))
    words2 = set(re.findall(r"\b\w+\b", text2.lower()))
    if not words1 or not words2:
        return 0.0
    intersection = words1.intersection(words2)
    union = words1.union(words2)
    return len(intersection) / len(union)


def _post_gemini(
    model: str,
    api_key: str,
    contents: list[dict[str, Any]],
    system_instruction: str,
    temperature: float = 0.7,
    max_tokens: int = 500,
    timeout: float = 12.0,
) -> str | None:
    """Execute a single generateContent request against the Gemini REST API."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload = {
        "system_instruction": {"parts": [{"text": system_instruction}]},
        "contents": contents,
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
        },
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates") or []
                if candidates:
                    candidate = candidates[0] or {}
                    content = candidate.get("content") or {}
                    parts = content.get("parts") or []
                    if parts and isinstance(parts[0], dict) and parts[0].get("text"):
                        return parts[0]["text"].strip()
            elif resp.status_code == 404:
                logger.info(f"Model {model} returned 404, will try fallback.")
            else:
                logger.warning(f"Gemini API returned {resp.status_code}: {resp.text[:120]}")
    except Exception as e:
        logger.warning(f"Gemini API request failed for {model}: {e}")

    return None


def call_gemini(
    contents: list[dict[str, Any]],
    system_instruction: str = PEBBLES_CORE_PRINCIPLES,
    temperature: float = 0.7,
    max_tokens: int = 500,
    timeout: float = 12.0,
) -> str | None:
    """Call Gemini with automatic model fallback across supported models."""
    api_key = _get_gemini_api_key()
    if not api_key:
        return None

    for model in GEMINI_MODELS:
        result = _post_gemini(
            model=model,
            api_key=api_key,
            contents=contents,
            system_instruction=system_instruction,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
        )
        if result:
            return result

    return None


def call_gemini_conversational(
    query: str,
    client_name: str,
    chat_history: list[dict[str, Any]] | None = None,
) -> str:
    """Generate a natural conversational or advisory response.

    Handles greetings, technical questions, explanations, and advice using rolling memory.
    """
    history = chat_history or []
    q_lower = query.lower().strip()
    words = q_lower.split()

    is_short_greeting = (
        len(words) <= 2
        or q_lower in ("hi", "hello", "hey", "sup", "yo", "morning", "howdy", "thanks", "thank you", "ok", "okay", "cool")
    )

    if is_short_greeting:
        max_tokens = 250
        system_instruction = (
            f"{PEBBLES_CORE_PRINCIPLES}\n\n"
            f"You are Pebbles, actively monitoring Rapid7 telemetry for **{client_name}**.\n"
            f"Respond in 2-4 friendly, conversational sentences. Greet the analyst warmly as Pebbles.\n"
            f"Be varied and natural. Do NOT use canned or scripted templates.\n"
            f"Do NOT output raw data tables or raw HTML."
        )
    else:
        max_tokens = 650
        system_instruction = (
            f"{PEBBLES_CORE_PRINCIPLES}\n\n"
            f"You are Pebbles, a trusted SOC Senior Analyst and AI companion actively monitoring Rapid7 for **{client_name}**.\n"
            f"The analyst is asking a question or following up on previous findings: '{query}'.\n"
            f"Answer them directly, insightfully, and conversationally in the first person.\n"
            f"Draw on the ongoing conversation context. If they are asking about an alert, actor, or finding discussed earlier, reference it directly.\n"
            f"Provide crisp, practical security analysis, context, or actionable remediation guidance.\n"
            f"Do NOT invent or generate unrequested data tables, mock telemetry, or raw HTML."
        )

    contents = format_conversation_for_model(
        system_prompt=system_instruction,
        chat_history=history,
        current_query=query,
    )

    # Attempt DeepSeek first if configured, falling back to Gemini
    reply = None
    if _get_deepseek_api_key():
        openai_msgs = _format_messages_for_openai(
            system_instruction=system_instruction,
            chat_history=history,
            current_query=query,
        )
        reply = call_deepseek(
            messages=openai_msgs,
            temperature=0.75,
            max_tokens=max_tokens,
        )

    if not reply:
        # Generation with Gemini
        reply = call_gemini(
            contents=contents,
            system_instruction=system_instruction,
            temperature=0.75,
            max_tokens=max_tokens,
        )

    # Check for similarity with previous assistant messages to prevent repetition
    if reply and history:
        recent_assistant_texts = [
            m.get("content", "")
            for m in history[-4:]
            if m.get("role") in ("assistant", "model")
        ]
        for past_text in recent_assistant_texts:
            if _calculate_similarity(reply, past_text) > 0.70:
                # High repetition detected: retry with higher temperature
                if _get_deepseek_api_key():
                    varied_openai_msgs = _format_messages_for_openai(
                        system_instruction=system_instruction,
                        chat_history=history,
                        current_query=f"{query}\n(Note: Please vary your phrasing so it is fresh and distinct from previous replies.)",
                    )
                    varied_reply = call_deepseek(
                        messages=varied_openai_msgs,
                        temperature=0.90,
                        max_tokens=max_tokens,
                    )
                    if varied_reply:
                        reply = varied_reply
                        break
                variation_contents = contents + [
                    {
                        "role": "user",
                        "parts": [
                            {
                                "text": "Please vary your reply so it sounds fresh and different from previous responses."
                            }
                        ],
                    }
                ]
                varied_reply = call_gemini(
                    contents=variation_contents,
                    system_instruction=system_instruction,
                    temperature=0.90,
                    max_tokens=max_tokens,
                )
                if varied_reply:
                    reply = varied_reply
                break

    if reply:
        return sanitize_markdown_text(reply)

    # Fallback only if both LLMs are absent or network unreachable
    return (
        f"Hey! I'm Pebbles, your SOC intelligence assistant, and I'm ready to help you analyze **{client_name}**'s security data. "
        f"We can check open investigations, track risky users, test collector health, "
        f"or run log searches. What would you like to look at?"
    )


def call_gemini_analytical(
    query: str,
    client_name: str,
    telemetry_records: list[dict[str, Any]],
    intent: str,
    chat_history: list[dict[str, Any]] | None = None,
    pagination_info: str | None = None,
) -> str | None:
    """Generate an analytical narrative interpreting real Rapid7 telemetry.

    Strictly grounded in provided records.
    """
    history = chat_history or []
    sample_records = telemetry_records[:8]
    telemetry_summary = json.dumps(sample_records, indent=2, default=str)

    context_prompt = (
        f"User query: '{query}'\n"
        f"Client organization: {client_name}\n"
        f"Analysis category: {intent}\n"
    )
    if pagination_info:
        context_prompt += f"Pagination / Data scope: {pagination_info}\n"

    system_instruction = (
        f"{PEBBLES_CORE_PRINCIPLES}\n\n"
        f"You are analyzing live Rapid7 telemetry for **{client_name}**.\n"
        f"Synthesize the findings into 2-4 concise, impactful paragraphs in the first person.\n"
        f"Reference real names, alert titles, priorities, and counts from the telemetry.\n"
        f"Do NOT invent figures or CVEs not in the telemetry.\n"
        f"If looking at a partial page (e.g. 15 items), mention the total scope clearly.\n"
        f"Conclude with 1-2 actionable next steps for the SOC team."
    )

    contents = format_conversation_for_model(
        system_prompt=system_instruction,
        chat_history=history,
        current_query=context_prompt,
        telemetry_context=telemetry_summary,
    )

    reply = None
    if _get_deepseek_api_key():
        openai_msgs = _format_messages_for_openai(
            system_instruction=system_instruction,
            chat_history=history,
            current_query=context_prompt,
            telemetry_context=telemetry_summary,
        )
        reply = call_deepseek(
            messages=openai_msgs,
            temperature=0.35,
            max_tokens=550,
        )

    if not reply:
        reply = call_gemini(
            contents=contents,
            system_instruction=system_instruction,
            temperature=0.35,  # lower temperature for grounded analysis
            max_tokens=550,
        )

    if reply:
        return sanitize_markdown_text(reply)

    return None


# Aliases for provider-neutral usage
call_llm_conversational = call_gemini_conversational
call_llm_analytical = call_gemini_analytical
call_llm = call_gemini
