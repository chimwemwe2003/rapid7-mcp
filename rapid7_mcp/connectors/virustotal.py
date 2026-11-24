"""VirusTotal Threat Intelligence Connector (API v3).

Provides strictly read-only, lookup-only threat intelligence for PUBLIC indicators:
- External IPv4/IPv6 addresses
- Public Domain names
- Public URLs (base64url-encoded lookup only, never submitted/scanned)
- File hashes (MD5, SHA-1, SHA-256)

Enforces:
- Code-level outbound data filter (RFC 1918, CGNAT, loopback, internal domains, emails strictly blocked)
- Strictly no uploads, scans, comments, votes, downloads, or write endpoints
- Rate limiting (4 req/min, 500 req/day on Public tier) with daily quota tracking
- Exponential backoff on HTTP 429
- Honest reporting: "X of Y engines flagged this", "Not found != Clean", "0 detections != Clean"
- Zero user/client data in cache (keyed solely by indicator_type:indicator_value)
- Secrets never logged or exposed in LLM context
"""

import base64
from collections import deque
from datetime import datetime, date, timezone
import ipaddress
import json
import logging
import re
import time
from typing import Any
import httpx

from rapid7_mcp.connectors.base import BaseConnector, ConnectionStatus, ToolDefinition

logger = logging.getLogger("pebbles.connectors.virustotal")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Public API free tier limits
PUBLIC_TIER_RPM = 4
PUBLIC_TIER_DAILY_LIMIT = 500

# Prohibited VirusTotal write/scan endpoints
PROHIBITED_VT_ENDPOINTS = (
    "/files",  # POST file upload
    "/urls",   # POST url submission/scan
    "/comments",
    "/votes",
    "/download",
    "/retrohunt",
    "/feeds",
    "/livehunt",
)

# Regex patterns for indicator validation
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class VirusTotalClientError(Exception):
    """Specific error raised for VirusTotal API operations."""
    def __init__(self, status_code: int, message: str, code: str = "VT_ERROR"):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.code = code


class OutboundFilterError(Exception):
    """Raised when an indicator is blocked by the outbound confidentiality filter."""
    def __init__(self, message: str, indicator: str, reason: str):
        super().__init__(message)
        self.indicator = indicator
        self.reason = reason
        self.error_code = reason


def encode_vt_url_id(url: str) -> str:
    """Encode a URL into VirusTotal API v3 URL identifier format.

    According to official VT API v3 documentation:
    The URL identifier is the base64 URL-safe representation of the complete URL string
    without trailing '=' padding characters.
    Ref: https://docs.virustotal.com/reference/url-info
    """
    clean_url = url.strip()
    encoded = base64.urlsafe_b64encode(clean_url.encode("utf-8")).decode("utf-8")
    return encoded.rstrip("=")


class OutboundDataFilter:
    """Enforces confidentiality boundary. Ensures NO private or internal data leaves for VirusTotal."""

    def __init__(self, internal_domains: list[str] | None = None, client_name: str | None = None):
        combined = list(internal_domains or []) + [
            "local", "internal", "corp", "lan", "home", "arpa", "localhost"
        ]
        if client_name:
            c_low = client_name.lower()
            if "napsa" in c_low:
                combined.append("napsa.co.zm")
            elif "znbs" in c_low:
                combined.append("znbs.co.zm")
        elif not internal_domains:
            combined.extend(["napsa.co.zm", "znbs.co.zm"])

        self.internal_domains = [
            d.lower().strip().lstrip(".")
            for d in combined
        ]

    def classify_indicator(self, indicator: str) -> tuple[str, str]:
        """Classify and sanitize an indicator. Returns (indicator_type, sanitized_value)."""
        val = indicator.strip()
        if not val:
            raise OutboundFilterError("Indicator is empty.", val, "EMPTY")

        # 0. Pronouns and reference words are never indicators
        PRONOUNS_AND_FILLERS = {"it", "that", "this", "them", "these", "those", "him", "her", "its", "their", "theirs"}
        if val.lower() in PRONOUNS_AND_FILLERS:
            raise OutboundFilterError(
                f"'{val}' is a pronoun or reference word, not a valid network indicator.",
                val,
                "PRONOUN_INDICATOR",
            )

        # 1. Emails are NEVER external reputation indicators
        if EMAIL_REGEX.match(val):
            raise OutboundFilterError(
                f"I won't send '{val}' to VirusTotal because it is an email address. "
                "VirusTotal is for public threat reputation lookups, not personal identifiers.",
                val,
                "EMAIL_BLOCKED",
            )

        # 2. IP Address check
        try:
            ip_obj = ipaddress.ip_address(val)
            if ip_obj.is_loopback:
                raise OutboundFilterError(
                    f"I won't send that IP (`{val}`) to VirusTotal because it is a loopback address.",
                    val,
                    "LOOPBACK_IP",
                )
            if ip_obj.is_link_local:
                raise OutboundFilterError(
                    f"I won't send that IP (`{val}`) to VirusTotal because it is a link-local address.",
                    val,
                    "LINK_LOCAL_IP",
                )
            if ip_obj.is_multicast:
                raise OutboundFilterError(
                    f"I won't send that IP (`{val}`) to VirusTotal because it is a multicast address.",
                    val,
                    "MULTICAST_IP",
                )
            if ip_obj.is_reserved or ip_obj.is_unspecified:
                raise OutboundFilterError(
                    f"I won't send that IP (`{val}`) to VirusTotal because it is a reserved network address.",
                    val,
                    "RESERVED_IP",
                )
            # CGNAT check (100.64.0.0/10)
            cgnat_net = ipaddress.ip_network("100.64.0.0/10")
            if ip_obj in cgnat_net:
                raise OutboundFilterError(
                    f"I won't send that IP (`{val}`) to VirusTotal because it is a Carrier-Grade NAT (CGNAT) address.",
                    val,
                    "CGNAT_IP",
                )
            if ip_obj.is_private:
                raise OutboundFilterError(
                    f"I won't send that IP (`{val}`) to VirusTotal because it is an internal RFC1918 private address.",
                    val,
                    "RFC1918_PRIVATE_IP",
                )
            return "ip", str(ip_obj)
        except ValueError:
            pass  # Not an IP address, proceed to domain/hash/url checks

        # 3. File Hash check (MD5, SHA-1, SHA-256)
        if MD5_REGEX.match(val) or SHA1_REGEX.match(val) or SHA256_REGEX.match(val):
            return "file", val.lower()

        # 4. URL check
        if val.startswith("http://") or val.startswith("https://"):
            from urllib.parse import urlparse
            parsed = urlparse(val)
            hostname = parsed.hostname or ""

            # Check if URL host is internal IP or domain
            if not hostname:
                raise OutboundFilterError("Invalid URL without hostname.", val, "INVALID_URL")

            # Check if host is private IP
            try:
                host_ip = ipaddress.ip_address(hostname)
                if host_ip.is_private or host_ip.is_loopback or host_ip.is_reserved:
                    raise OutboundFilterError(
                        f"I won't send that URL (`{val}`) to VirusTotal because the host is an internal IP.",
                        val,
                        "URL_INTERNAL_HOST",
                    )
            except ValueError:
                pass

            # Check if host matches internal domains
            h_lower = hostname.lower()
            if any(h_lower == d or h_lower.endswith(f".{d}") for d in self.internal_domains) or "." not in h_lower:
                raise OutboundFilterError(
                    f"I won't send that URL to VirusTotal because host '{hostname}' is an internal domain.",
                    val,
                    "URL_INTERNAL_DOMAIN",
                )

            # Strip sensitive query parameters by default for confidentiality
            sanitized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            return "url", sanitized_url

        # 5. Domain name check
        d_lower = val.lower().rstrip(".")
        if any(d_lower == d or d_lower.endswith(f".{d}") for d in self.internal_domains):
            raise OutboundFilterError(
                f"I won't send domain `{val}` to VirusTotal because it matches your configured internal organization domains.",
                val,
                "INTERNAL_DOMAIN",
            )

        # Single-label hostnames without dot (e.g. "lev-it003060", "dc01")
        if "." not in d_lower:
            raise OutboundFilterError(
                f"I won't send hostname `{val}` to VirusTotal because it looks like an internal local machine name.",
                val,
                "LOCAL_HOSTNAME",
            )

        # Basic domain validation
        if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", d_lower):
            return "domain", d_lower

        raise OutboundFilterError(
            f"I won't send '{val}' to VirusTotal because it does not match a valid public IP, domain, URL, or hash.",
            val,
            "INVALID_INDICATOR",
        )

    validate_indicator = classify_indicator


class RateLimiterAndQuotaTracker:
    """Enforces VirusTotal per-minute rate limits and tracks daily quota consumption."""

    def __init__(self, tier: str = "public", custom_rpm: int | None = None, custom_daily: int | None = None):
        self.tier = tier.lower()
        self.rpm_limit = custom_rpm or (PUBLIC_TIER_RPM if self.tier == "public" else 100)
        self.daily_limit = custom_daily or (PUBLIC_TIER_DAILY_LIMIT if self.tier == "public" else 100000)

        self._request_timestamps: deque[float] = deque()
        self._daily_count = 0
        self._current_date = date.today()

    def _reset_daily_if_new_day(self) -> None:
        today = date.today()
        if today != self._current_date:
            self._current_date = today
            self._daily_count = 0

    def get_quota_status(self) -> dict[str, Any]:
        """Return the current daily quota and rate limit status."""
        self._reset_daily_if_new_day()
        return {
            "tier": self.tier,
            "requests_today": self._daily_count,
            "daily_limit": self.daily_limit,
            "daily_remaining": max(0, self.daily_limit - self._daily_count),
            "rpm_limit": self.rpm_limit,
        }

    def check_and_record(self) -> None:
        """Check rate limit and daily quota. Sleep slightly if necessary or raise quota exhausted."""
        self._reset_daily_if_new_day()

        if self._daily_count >= self.daily_limit:
            raise VirusTotalClientError(
                429,
                f"VirusTotal daily quota of {self.daily_limit} requests has been exhausted for today. "
                "No further lookups can be performed until the quota resets tomorrow.",
                code="DAILY_QUOTA_EXHAUSTED",
            )

        now = time.time()
        # Clean timestamps older than 60 seconds
        while self._request_timestamps and now - self._request_timestamps[0] > 60.0:
            self._request_timestamps.popleft()

        # If rate limit reached within current 60s window, throttle or raise
        if len(self._request_timestamps) >= self.rpm_limit:
            oldest = self._request_timestamps[0]
            wait_time = max(0.1, 60.0 - (now - oldest))
            if wait_time > 15.0:
                raise VirusTotalClientError(
                    429,
                    f"VirusTotal {self.tier.upper()} rate limit ({self.rpm_limit} req/min) active. Please back off for {int(wait_time)}s.",
                    code="RATE_LIMIT_EXCEEDED",
                )
            time.sleep(wait_time)

        self._request_timestamps.append(time.time())
        self._daily_count += 1


class IndicatorCache:
    """In-memory TTL cache for public VirusTotal facts. Zero user or tenant data stored."""

    def __init__(self, default_ttl_seconds: int = 21600):  # 6 hours default
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self.default_ttl = default_ttl_seconds

    def _cache_key(self, indicator_type: str, indicator_value: str) -> str:
        return f"{indicator_type.lower()}:{indicator_value.lower()}"

    def get(self, indicator_type: str, indicator_value: str) -> dict[str, Any] | None:
        key = self._cache_key(indicator_type, indicator_value)
        item = self._cache.get(key)
        if not item:
            return None
        expires_at, data = item
        if time.time() > expires_at:
            del self._cache[key]
            return None
        return data

    def set(self, indicator_type: str, indicator_value: str, data: dict[str, Any], ttl_seconds: int | None = None) -> None:
        key = self._cache_key(indicator_type, indicator_value)
        ttl = ttl_seconds or self.default_ttl
        self._cache[key] = (time.time() + ttl, data)


# Global connector instances
_global_limiter = RateLimiterAndQuotaTracker(tier="public")
_global_cache = IndicatorCache()


class VirusTotalConnector(BaseConnector):
    """VirusTotal Threat Intelligence Connector (API v3)."""

    def __init__(
        self,
        tier: str = "public",
        api_tier: str | None = None,
        rate_limit_per_min: int | None = None,
        daily_quota: int | None = None,
        key_mode: str = "per_user",
        shared_key: str = "",
        internal_domains: list[str] | None = None,
        timeout: float = 12.0,
        transport: httpx.BaseTransport | None = None,
    ):
        chosen_tier = (api_tier or tier).lower()
        self.tier = chosen_tier
        self.key_mode = key_mode.lower()
        self.shared_key = shared_key.strip()
        self.timeout = timeout
        self.filter = OutboundDataFilter(internal_domains=internal_domains)
        if rate_limit_per_min is not None or daily_quota is not None:
            self.limiter = RateLimiterAndQuotaTracker(
                tier=self.tier,
                custom_rpm=rate_limit_per_min,
                custom_daily=daily_quota,
            )
        else:
            self.limiter = _global_limiter
        self.cache = _global_cache
        self._transport = transport

    @property
    def provider_name(self) -> str:
        return "VirusTotal"

    def _create_client(self) -> httpx.Client:
        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if getattr(self, "_transport", None) is not None:
            kwargs["transport"] = self._transport
        return httpx.Client(**kwargs)

    def _resolve_api_key(self, credentials: dict[str, Any]) -> str:
        """Resolve API key based on key_mode (per_user vs shared)."""
        if self.key_mode == "shared" and self.shared_key:
            return self.shared_key
        key = credentials.get("api_key") or credentials.get("x-apikey") or credentials.get("key") or ""
        return str(key).strip()

    def verify_connection(self, credentials: dict[str, Any], **kwargs: Any) -> ConnectionStatus:
        """Verify VirusTotal API key, tier, and probe reachability using a harmless known indicator."""
        api_key = self._resolve_api_key(credentials)
        if not api_key:
            return ConnectionStatus(
                connected=False,
                provider=self.provider_name,
                target=VT_BASE_URL,
                authenticated=False,
                message="VirusTotal API key is missing. Paste your key in the sidebar.",
                capabilities={"tier": self.tier},
            )

        start = time.time()
        # Probe known public DNS IP 8.8.8.8
        test_url = f"{VT_BASE_URL}/ip_addresses/8.8.8.8"
        headers = {"x-apikey": api_key, "Accept": "application/json"}

        try:
            with self._create_client() as client:
                resp = client.get(test_url, headers=headers)
                latency_ms = int((time.time() - start) * 1000)

                if resp.status_code == 200:
                    quota = self.limiter.get_quota_status()
                    is_public = self.tier == "public"
                    msg = (
                        f"Connected to VirusTotal API v3 in {latency_ms}ms ({self.tier.upper()} Tier). "
                        f"Daily Budget: {quota['requests_today']}/{quota['daily_limit']} used."
                    )
                    if is_public:
                        msg += " ⚠️ Note: Free Public API key terms prohibit commercial SOC deployment without a business license."

                    masked_key = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else "••••••••"
                    rem_quota = quota.get("daily_remaining", self.limiter.daily_limit)
                    return ConnectionStatus(
                        connected=True,
                        provider=self.provider_name,
                        target=VT_BASE_URL,
                        authenticated=True,
                        read_only=True,
                        latency_ms=latency_ms,
                        message=msg,
                        capabilities={
                            "tier": self.tier,
                            "key_mode": self.key_mode,
                            "file_lookup": True,
                            "ip_lookup": True,
                            "domain_lookup": True,
                            "url_lookup": True,
                            "quota": quota,
                        },
                        details={
                            "masked_key": masked_key,
                            "daily_quota_remaining": rem_quota,
                            "requests_today": quota.get("requests_today", 0),
                            "daily_limit": quota.get("daily_limit", self.limiter.daily_limit),
                        },
                    )
                elif resp.status_code == 401:
                    return ConnectionStatus(
                        connected=False,
                        provider=self.provider_name,
                        target=VT_BASE_URL,
                        authenticated=False,
                        latency_ms=latency_ms,
                        message="Invalid VirusTotal API Key (HTTP 401). Verify the key pasted in the sidebar.",
                        capabilities={"tier": self.tier},
                    )
                elif resp.status_code == 403:
                    return ConnectionStatus(
                        connected=False,
                        provider=self.provider_name,
                        target=VT_BASE_URL,
                        authenticated=False,
                        latency_ms=latency_ms,
                        message="VirusTotal access forbidden (HTTP 403). Key may lack required permissions or account is suspended.",
                        capabilities={"tier": self.tier},
                    )
                elif resp.status_code == 429:
                    return ConnectionStatus(
                        connected=False,
                        provider=self.provider_name,
                        target=VT_BASE_URL,
                        authenticated=True,
                        latency_ms=latency_ms,
                        message="VirusTotal rate limit or daily quota reached (HTTP 429).",
                        capabilities={"tier": self.tier},
                    )
                else:
                    return ConnectionStatus(
                        connected=False,
                        provider=self.provider_name,
                        target=VT_BASE_URL,
                        authenticated=False,
                        latency_ms=latency_ms,
                        message=f"VirusTotal verification failed with HTTP {resp.status_code}: {resp.text[:140]}",
                    )
        except httpx.ConnectError as e:
            return ConnectionStatus(
                connected=False,
                provider=self.provider_name,
                target=VT_BASE_URL,
                authenticated=False,
                message=f"Network error connecting to VirusTotal: {str(e)}",
            )
        except httpx.TimeoutException:
            return ConnectionStatus(
                connected=False,
                provider=self.provider_name,
                target=VT_BASE_URL,
                authenticated=False,
                message="Connection timed out reaching https://www.virustotal.com.",
            )

    def get_tools(self) -> list[ToolDefinition]:
        """Return allowed read-only VirusTotal tools."""
        return [
            ToolDefinition(
                name="vt_lookup_indicator",
                description="Look up reputation, detection counts, and analysis facts for a public IP, domain, URL, or file hash.",
                provider=self.provider_name,
                parameters={
                    "indicator": {"type": "string", "description": "Public IP, public domain, public URL, or file hash (MD5/SHA-1/SHA-256).", "required": True},
                },
            ),
        ]

    def _execute_api_get(self, endpoint_path: str, api_key: str) -> tuple[int, dict[str, Any], int]:
        """Execute a read-only GET against VirusTotal with rate limiting and backoff."""
        # Safety check: enforce GET only and ensure no write endpoints
        for prohibited in PROHIBITED_VT_ENDPOINTS:
            if endpoint_path == prohibited or endpoint_path.startswith(f"{prohibited}/"):
                if endpoint_path.startswith("/files") and len(endpoint_path.split("/")) == 3:
                    pass  # /files/{hash} GET is allowed
                elif endpoint_path.startswith("/urls") and len(endpoint_path.split("/")) == 3:
                    pass  # /urls/{id} GET is allowed
                else:
                    raise VirusTotalClientError(403, f"Endpoint '{endpoint_path}' is not an allowed read-only lookup.", code="PROHIBITED_ENDPOINT")

        self.limiter.check_and_record()
        url = f"{VT_BASE_URL}{endpoint_path}"
        headers = {"x-apikey": api_key, "Accept": "application/json"}

        start = time.time()
        # Backoff on 429
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                with self._create_client() as client:
                    resp = client.get(url, headers=headers)
                    latency = int((time.time() - start) * 1000)

                    if resp.status_code == 200:
                        return 200, resp.json(), latency
                    elif resp.status_code == 404:
                        return 404, {}, latency
                    elif resp.status_code == 429:
                        if attempt < max_retries:
                            backoff_seconds = (attempt + 1) * 3
                            logger.warning("VirusTotal 429 received. Backing off %ss...", backoff_seconds)
                            time.sleep(backoff_seconds)
                            continue
                        raise VirusTotalClientError(429, "VirusTotal rate limit exceeded after retries.", code="RATE_LIMITED")
                    elif resp.status_code == 401:
                        raise VirusTotalClientError(401, "Invalid VirusTotal API Key.", code="INVALID_KEY")
                    elif resp.status_code == 403:
                        raise VirusTotalClientError(403, "Access forbidden. Key lacks access or endpoint is premium-only.", code="FORBIDDEN")
                    else:
                        raise VirusTotalClientError(resp.status_code, f"VirusTotal HTTP {resp.status_code}: {resp.text[:140]}")
            except httpx.TimeoutException:
                if attempt < max_retries:
                    continue
                raise VirusTotalClientError(504, "VirusTotal request timed out.", code="TIMEOUT")
            except httpx.ConnectError as e:
                raise VirusTotalClientError(502, f"Network error contacting VirusTotal: {str(e)}", code="NETWORK_ERROR")

        return 500, {}, 0

    def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        credentials: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute a read-only VirusTotal lookup."""
        if tool_name != "vt_lookup_indicator":
            if any(k in tool_name.lower() for k in ["upload", "submit", "comment", "rescan", "post"]):
                raise VirusTotalClientError(
                    403,
                    f"Tool '{tool_name}' violates the strict read-only no-write guarantee. VirusTotal submissions, uploads, and comments are blocked.",
                    code="NO_WRITE_VIOLATION",
                )
            raise VirusTotalClientError(404, f"Tool '{tool_name}' not supported by VirusTotal connector.")

        api_key = self._resolve_api_key(credentials)
        if not api_key:
            raise VirusTotalClientError(401, "VirusTotal API Key missing. Please provide a key in the sidebar.", code="NO_KEY")

        raw_indicator = str(arguments.get("indicator", "")).strip()
        # 1. Enforce outbound confidentiality filter
        ind_type, sanitized_val = self.filter.classify_indicator(raw_indicator)

        # 2. Check cache (keyed solely by type and sanitized value)
        cached_result = self.cache.get(ind_type, sanitized_val)
        if cached_result:
            cached_result["cached"] = True
            return cached_result

        # 3. Determine endpoint path
        if ind_type == "ip":
            endpoint = f"/ip_addresses/{sanitized_val}"
        elif ind_type == "domain":
            endpoint = f"/domains/{sanitized_val}"
        elif ind_type == "file":
            endpoint = f"/files/{sanitized_val}"
        elif ind_type == "url":
            url_id = encode_vt_url_id(sanitized_val)
            endpoint = f"/urls/{url_id}"
        else:
            raise VirusTotalClientError(400, f"Unsupported indicator type: {ind_type}")

        # 4. Execute query
        status_code, data, latency = self._execute_api_get(endpoint, api_key)

        # 5. Format facts
        if status_code == 404:
            result = {
                "provider": self.provider_name,
                "tool_name": tool_name,
                "indicator": sanitized_val,
                "indicator_type": ind_type,
                "endpoint": endpoint,
                "found": False,
                "status": "NOT_FOUND",
                "message": (
                    f"VirusTotal has **no record** for this {ind_type} (`{sanitized_val}`). "
                    "Note: 'Not found' means VirusTotal has not previously analyzed this indicator; "
                    "it does not guarantee that it is safe or benign."
                ),
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "latency_ms": latency,
                "cached": False,
            }
            self.cache.set(ind_type, sanitized_val, result, ttl_seconds=3600)  # 1hr cache for 404s
            return result

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        analysis_date_ts = attributes.get("last_analysis_date")
        analysis_date_str = (
            datetime.fromtimestamp(analysis_date_ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            if analysis_date_ts
            else "Unknown"
        )
        reputation = attributes.get("reputation", 0)
        categories = list(attributes.get("categories", {}).values())[:5]

        # Construct honest, objective assessment
        if malicious == 0 and suspicious == 0:
            assessment = (
                f"**0 of {total_engines} engines** flagged this {ind_type} as malicious. "
                "While no known security engines report threats at this time, "
                "0 detections does not definitively guarantee cleanliness."
            )
        elif malicious >= 3:
            assessment = (
                f"⚠️ **{malicious} of {total_engines} security engines** flagged this {ind_type} as **MALICIOUS** "
                f"(Suspicious: {suspicious}). High confidence threat indicator."
            )
        else:
            assessment = (
                f"🔍 **{malicious} of {total_engines} security engines** flagged this as malicious ({suspicious} suspicious). "
                "Low to moderate detection count; verify against local logs and behavior before confirming compromise."
            )

        result = {
            "provider": self.provider_name,
            "tool_name": tool_name,
            "indicator": sanitized_val,
            "indicator_type": ind_type,
            "endpoint": endpoint,
            "found": True,
            "status": "MALICIOUS" if malicious >= 3 else ("SUSPICIOUS" if malicious > 0 or suspicious > 0 else "CLEAN_ENGINES"),
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "total_engines": total_engines,
            "last_analysis_date": analysis_date_str,
            "reputation_score": reputation,
            "categories": categories,
            "assessment": assessment,
            "latency_ms": latency,
            "cached": False,
        }

        # Cache valid lookups (6 hours for IP/domain/url, 24 hours for file hash)
        ttl = 86400 if ind_type == "file" else 21600
        self.cache.set(ind_type, sanitized_val, result, ttl_seconds=ttl)
        return result

    def lookup_indicator(self, indicator: str, credentials: dict[str, Any]) -> dict[str, Any]:
        """Convenience method to execute vt_lookup_indicator tool."""
        return self.execute_tool("vt_lookup_indicator", {"indicator": indicator}, credentials)
