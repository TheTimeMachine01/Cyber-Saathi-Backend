import os
import sys
import json
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import requests
import validators

try:
    import whois  # python-whois
except ImportError:  # Graceful degradation if whois is missing
    whois = None  # type: ignore

from urllib.parse import urlparse
from datetime import datetime, timezone


VT_API_ENV_VAR = "VT_API_KEY"
PHONEINFOGA_ENV_VAR = "PHONEINFOGA_PATH"

# Optional built-in VirusTotal API key fallback.
# This key will be used automatically when the VT_API_KEY
# environment variable is not set.
DEFAULT_VT_API_KEY = "" # Set via VT_API_KEY environment variable

# Simple in-memory caches to avoid duplicate lookups
_domain_ip_cache: Dict[str, str] = {}
_ip_info_cache: Dict[str, Dict[str, Any]] = {}


def get_vt_api_key() -> Optional[str]:
    """Return VirusTotal API key from env or built-in fallback.

    Order of precedence:
    1. VT_API_KEY environment variable
    2. DEFAULT_VT_API_KEY constant (if not left as placeholder)
    """

    api_key = os.getenv(VT_API_ENV_VAR)
    if api_key and api_key.strip():
        return api_key.strip()

    # Fallback to built-in key if configured
    if DEFAULT_VT_API_KEY and DEFAULT_VT_API_KEY.strip() and DEFAULT_VT_API_KEY != "PUT_YOUR_API_KEY_HERE":
        return DEFAULT_VT_API_KEY.strip()

    return None


def get_phoneinfoga_command() -> List[str]:
    """Return the base PhoneInfoga command, honoring an override env var.

    If PHONEINFOGA_PATH is set, use that exact path as the executable.
    Otherwise, fall back to `phoneinfoga` (must be in PATH).
    """

    override = os.getenv(PHONEINFOGA_ENV_VAR)
    if override and override.strip():
        return [override.strip()]

    # Auto-detect a local PhoneInfoga binary next to this script.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define candidates based on OS
    if os.name == 'nt':
        local_candidates = [
            os.path.join(script_dir, "phoneinfoga.exe"),
            os.path.join(script_dir, "phoneinfoga_Windows_arm64", "phoneinfoga.exe"),
        ]
    else:
        local_candidates = [
            os.path.join(script_dir, "phoneinfoga"),
            os.path.join(script_dir, "bin", "phoneinfoga"), # Common for local installs
            "/usr/local/bin/phoneinfoga",
        ]
        
    for path in local_candidates:
        if os.path.isfile(path):
            return [path]

    # Fallback to CLI in PATH
    return ["phoneinfoga"]


def detect_input(user_input: str) -> str:
    """Detect type of input: url, domain, phone, apk, or unknown.

    Order of checks is important to avoid misclassification.
    """
    value = user_input.strip()

    # APK detection by extension
    if value.lower().endswith(".apk"):
        return "apk"

    # Phone number detection (basic, international style)
    # Normalize by removing spaces, hyphens, parentheses
    normalized = re.sub(r"[\s\-()]+", "", value)
    if re.fullmatch(r"\+?[0-9]{7,15}", normalized):
        return "phone"

    # URL detection (must include scheme or recognizable structure)
    if validators.url(value):
        return "url"

    # Domain detection (no scheme, valid domain)
    if validators.domain(value):
        return "domain"

    return "unknown"


def vt_request(
    method: str,
    url: str,
    api_key: str,
    **kwargs: Any,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Perform a VirusTotal API request and return (json, error_message)."""
    headers = kwargs.pop("headers", {}) or {}
    headers["x-apikey"] = api_key

    try:
        response = requests.request(method, url, headers=headers, timeout=30, **kwargs)
    except requests.RequestException as exc:  # Network / timeout / connection errors
        return None, f"Network error while contacting VirusTotal: {exc}"

    try:
        data = response.json()
    except ValueError:
        data = None

    if not response.ok:
        # Include HTTP status and any JSON payload we could parse
        if data is not None:
            return None, f"VirusTotal API error {response.status_code}: {data}"
        return None, f"VirusTotal API error {response.status_code}: {response.text}"

    if not isinstance(data, dict):
        return None, "Unexpected VirusTotal response format"

    return data, None


def vt_lookup_url(url_value: str) -> Dict[str, Any]:
    """Lookup a URL in VirusTotal (v3).

    Returns a structured dict including error information if any.
    """
    api_key = get_vt_api_key()
    if not api_key:
        return {
            "status": "error",
            "error": f"Missing {VT_API_ENV_VAR} environment variable",
        }

    vt_url = "https://www.virustotal.com/api/v3/urls"
    data, err = vt_request("POST", vt_url, api_key, data={"url": url_value})
    if err:
        return {"status": "error", "error": err}

    return {"status": "ok", "response": data}


def vt_lookup_domain(domain: str) -> Dict[str, Any]:
    """Lookup a domain in VirusTotal (v3)."""
    api_key = get_vt_api_key()
    if not api_key:
        return {
            "status": "error",
            "error": f"Missing {VT_API_ENV_VAR} environment variable",
        }

    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    data, err = vt_request("GET", vt_url, api_key)
    if err:
        return {"status": "error", "error": err}

    return {"status": "ok", "response": data}


def vt_scan_apk(file_path: str) -> Dict[str, Any]:
    """Upload an APK file to VirusTotal for scanning and return response."""
    api_key = get_vt_api_key()
    if not api_key:
        return {
            "status": "error",
            "error": f"Missing {VT_API_ENV_VAR} environment variable",
        }

    if not os.path.isfile(file_path):
        return {
            "status": "error",
            "error": f"APK file not found: {file_path}",
        }

    vt_url = "https://www.virustotal.com/api/v3/files"

    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            data, err = vt_request("POST", vt_url, api_key, files=files)
    except OSError as exc:
        return {"status": "error", "error": f"Error reading APK file: {exc}"}

    if err:
        return {"status": "error", "error": err}

    return {"status": "ok", "response": data}


def whois_lookup(domain: str) -> Dict[str, Any]:
    """Perform WHOIS lookup using python-whois.

    Returns a JSON-serializable dict, or an error structure.
    """
    if whois is None:
        return {
            "status": "error",
            "error": "python-whois library not installed",
        }

    try:
        result = whois.whois(domain)
    except Exception as exc:  # WHOIS queries can be unreliable
        return {"status": "error", "error": f"WHOIS lookup failed: {exc}"}

    # Convert WHOIS object to a JSON-serializable dict using default=str
    try:
        # First, coerce the raw result into something JSON can handle by
        # letting json.dumps convert unsupported types (e.g., datetime) via str().
        coerced = json.loads(json.dumps(result, default=str))
    except Exception:
        coerced = {"raw": str(result)}

    return {"status": "ok", "response": coerced}


def _parse_datetime(value: Any) -> Optional[datetime]:
    """Best-effort parsing of various datetime formats into a UTC datetime.

    Supports:
    - UNIX timestamps (int / float / str digits)
    - ISO-like strings from WHOIS / VT.
    Returns None if parsing fails.
    """

    if value is None:
        return None

    # Numeric timestamps
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError):
            return None

    text = str(value).strip()
    if not text:
        return None

    # Pure digit string treated as epoch seconds
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            pass

    # Try fromisoformat (handles 'YYYY-MM-DD HH:MM:SS+00:00' etc.)
    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    # Fallback: several common WHOIS/HTTP date formats
    fmts = [
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    return None


def extract_domain_metadata(
    target: str,
    input_type: str,
    vt_result: Optional[Dict[str, Any]] = None,
    whois_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Extract enriched metadata from URL/domain using VT and WHOIS.

    Returns a JSON-serializable dictionary including:
    - basic URL/domain components
    - domain age (days)
    - registrar details
    - hosting IP
    - name servers
    - SSL certificate issuer and validity window.
    """

    metadata: Dict[str, Any] = {"raw": target, "input_type": input_type}

    # Basic structural metadata
    hostname: Optional[str] = None
    if input_type == "url":
        parsed = urlparse(target)
        hostname = parsed.hostname
        metadata.update(
            {
                "scheme": parsed.scheme,
                "hostname": parsed.hostname,
                "path": parsed.path,
                "query": parsed.query,
                "is_https": parsed.scheme.lower() == "https",
            }
        )
        if hostname:
            metadata["domain"] = hostname
    elif input_type == "domain":
        hostname = target
        metadata.update(
            {
                "scheme": None,
                "hostname": target,
                "domain": target,
                "is_https": None,
            }
        )

    # Defaults for enriched fields
    metadata.update(
        {
            "registrar": None,
            "registrar_url": None,
            "registrar_abuse_email": None,
            "creation_date": None,
            "expiration_date": None,
            "age_days": None,
            "hosting_ip": None,
            "name_servers": None,
            "ssl_issuer": None,
            "ssl_valid_from": None,
            "ssl_valid_to": None,
        }
    )

    # WHOIS-based enrichment
    whois_data: Optional[Dict[str, Any]] = None
    if whois_result and isinstance(whois_result, dict) and whois_result.get("status") == "ok":
        whois_data = whois_result.get("response")  # type: ignore[assignment]

    if isinstance(whois_data, dict):
        registrar = whois_data.get("registrar")
        if registrar:
            metadata["registrar"] = registrar

        # Additional registrar details when available
        registrar_url = (
            whois_data.get("registrar_url")
            or whois_data.get("referral_url")
            or whois_data.get("url")
        )
        if registrar_url:
            metadata["registrar_url"] = registrar_url

        abuse_email = (
            whois_data.get("registrar_abuse_contact_email")
            or whois_data.get("abuse_email")
        )
        if abuse_email:
            metadata["registrar_abuse_email"] = abuse_email

        creation = whois_data.get("creation_date")
        expiry = whois_data.get("expiration_date") or whois_data.get("expiry_date")

        # Some WHOIS libraries may return lists for these fields
        if isinstance(creation, list) and creation:
            creation = creation[0]
        if isinstance(expiry, list) and expiry:
            expiry = expiry[0]

        creation_dt = _parse_datetime(creation)
        expiry_dt = _parse_datetime(expiry)

        metadata["creation_date"] = creation_dt.isoformat() if creation_dt else None
        metadata["expiration_date"] = expiry_dt.isoformat() if expiry_dt else None

        if creation_dt:
            age = datetime.now(timezone.utc) - creation_dt
            metadata["age_days"] = max(age.days, 0)

        ns = whois_data.get("name_servers")
        if isinstance(ns, (list, tuple)):
            metadata["name_servers"] = list(ns)
        elif isinstance(ns, str):
            metadata["name_servers"] = [ns]

    # VirusTotal-based enrichment
    vt_attr: Optional[Dict[str, Any]] = None
    if vt_result and isinstance(vt_result, dict) and vt_result.get("status") == "ok":
        try:
            vt_attr = vt_result["response"]["data"]["attributes"]  # type: ignore[index]
        except Exception:
            vt_attr = None

    if isinstance(vt_attr, dict):
        # Hosting IP from last A record
        dns_records = vt_attr.get("last_dns_records") or []
        if isinstance(dns_records, list):
            for rec in dns_records:
                if isinstance(rec, dict) and rec.get("type") == "A" and rec.get("value"):
                    metadata["hosting_ip"] = rec["value"]
                    break

        # SSL certificate details
        cert = vt_attr.get("last_https_certificate") or {}
        if isinstance(cert, dict):
            issuer = cert.get("issuer", {})
            if isinstance(issuer, dict):
                cn = issuer.get("CN")
                if cn:
                    metadata["ssl_issuer"] = cn

            validity = cert.get("validity", {})
            if isinstance(validity, dict):
                nb = validity.get("not_before")
                na = validity.get("not_after")
                nb_dt = _parse_datetime(nb)
                na_dt = _parse_datetime(na)
                metadata["ssl_valid_from"] = nb_dt.isoformat() if nb_dt else None
                metadata["ssl_valid_to"] = na_dt.isoformat() if na_dt else None

        # Fall back to VT creation_date if WHOIS failed
        if metadata.get("creation_date") is None:
            vt_creation = vt_attr.get("creation_date")
            creation_dt = _parse_datetime(vt_creation)
            if creation_dt:
                metadata["creation_date"] = creation_dt.isoformat()
                age = datetime.now(timezone.utc) - creation_dt
                metadata["age_days"] = max(age.days, 0)

    return metadata


def analyze_website(user_input: str, input_type: str) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """Fetch and analyze website content for a URL or domain.

    Extracts basic web intelligence such as title, presence of login forms,
    and financial phishing-related keywords.
    Returns (website_analysis_dict, errors_list).
    """

    errors: List[Dict[str, str]] = []

    # Decide URLs to attempt
    urls_to_try: List[str] = []
    if input_type == "url":
        urls_to_try.append(user_input)
    elif input_type == "domain":
        urls_to_try.append(f"https://{user_input}")
        urls_to_try.append(f"http://{user_input}")
    else:
        return {"status": "error", "error": "Website analysis only for URL/domain"}, errors

    last_exc: Optional[Exception] = None
    response = None
    final_url: Optional[str] = None

    for url in urls_to_try:
        try:
            response = requests.get(url, timeout=20)
            final_url = response.url
            break
        except requests.RequestException as exc:
            last_exc = exc
            continue

    if response is None:
        msg = f"Failed to fetch website content: {last_exc}" if last_exc else "Failed to fetch website content"
        errors.append({"component": "website", "message": msg})
        return {"status": "error", "error": msg}, errors

    html = response.text or ""
    html_lower = html.lower()

    # Title extraction
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip() if title_match else None

    # Meta description extraction (very simple heuristic)
    meta_desc_match = re.search(
        r"<meta[^>]+name=['\"]description['\"][^>]*content=['\"](.*?)['\"]",
        html,
        re.IGNORECASE | re.DOTALL,
    )
    meta_description = meta_desc_match.group(1).strip() if meta_desc_match else None

    # Login form detection
    has_form = "<form" in html_lower
    login_indicators = ["password", "login", "log in", "sign in", "signin", "username"]
    login_form_detected = has_form and any(token in html_lower for token in login_indicators)

    # Financial / phishing terms detection
    financial_phrases = [
        "verify account",
        "bank login",
        "credit card",
        "update payment",
        "otp verification",
        "update your payment",
        "confirm your account",
    ]
    matched_phrases = [phrase for phrase in financial_phrases if phrase in html_lower]
    financial_keywords_detected = bool(matched_phrases)

    website_analysis = {
        "status": "ok",
        "url": final_url or urls_to_try[0],
        "http_status": response.status_code,
        "title": title,
        "meta_description": meta_description,
        "login_form_detected": login_form_detected,
        "financial_keywords_detected": financial_keywords_detected,
        "financial_keywords_matched": matched_phrases,
    }

    return website_analysis, errors


def analyze_url(user_input: str, input_type: str) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """Analyze a URL or domain: VirusTotal, WHOIS, metadata.

    Returns (analysis_dict, errors_list).
    """
    errors: List[Dict[str, str]] = []

    # Normalize domain for WHOIS / VT domain lookup
    if input_type == "url":
        parsed = urlparse(user_input)
        domain = parsed.hostname or ""
    else:
        domain = user_input.strip()

    # VirusTotal
    if input_type == "url":
        vt_result = vt_lookup_url(user_input)
    else:
        vt_result = vt_lookup_domain(domain)

    if vt_result.get("status") == "error":
        errors.append({"component": "virustotal", "message": vt_result.get("error", "Unknown error")})

    # WHOIS
    whois_result = whois_lookup(domain) if domain else {
        "status": "error",
        "error": "Empty domain after parsing",
    }
    if whois_result.get("status") == "error":
        errors.append({"component": "whois", "message": whois_result.get("error", "Unknown error")})

    # Metadata (uses VT + WHOIS when available)
    metadata = extract_domain_metadata(
        user_input if input_type == "url" else domain,
        input_type,
        vt_result,
        whois_result,
    )

    # Resolve IP once and reuse for hosting + IP intelligence
    hosting: Any = "NA"
    ip_information: Any = "NA"

    if domain:
        ip_address, dns_error = resolve_domain_ip(domain)
        if dns_error:
            errors.append({"component": "dns", "message": dns_error})

        if ip_address:
            # If metadata doesn't already have a hosting_ip from VT, set it from DNS
            if not metadata.get("hosting_ip"):
                metadata["hosting_ip"] = ip_address

            ip_info, ip_err = get_ip_information(ip_address)
            if ip_err:
                errors.append({"component": "ip_intel", "message": ip_err})
            if ip_info is not None:
                ip_information = ip_info

                hosting_info, hosting_err = get_hosting_provider(ip_info)
                if hosting_err:
                    errors.append({"component": "hosting", "message": hosting_err})
                if hosting_info is not None:
                    hosting = hosting_info

    # Website content analysis
    website_analysis, web_errors = analyze_website(user_input if input_type == "url" else domain, input_type)
    errors.extend(web_errors)

    analysis = {
        "virustotal": vt_result,
        "whois": whois_result,
        "domain_metadata": metadata,
        "hosting": hosting,
        "ip_information": ip_information,
        "website_analysis": website_analysis,
        "phoneinfoga": "NA",
        "apk_scan": "NA",
    }

    return analysis, errors


def parse_phoneinfoga_output(stdout_text: str, indicator: Optional[str] = None) -> Dict[str, Any]:
    """Parse PhoneInfoga CLI stdout into structured fields.

    Expected patterns in stdout (order may vary):

        Raw local: 09828565438
        Local: 098285 65438
        E164: +919828565438
        International: 919828565438
        Country: IN
        2 scanner(s) succeeded

    Returns a dictionary safe for JSON serialization.
    """

    text = stdout_text or ""

    def _match(pattern: str) -> Optional[str]:
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1).strip() if m else None

    raw_local = _match(r"Raw local:\s*(.+)")
    local = _match(r"Local:\s*(.+)")
    if local is not None:
        local_number = local.replace(" ", "")
    else:
        local_number = raw_local.replace(" ", "") if raw_local is not None else None

    e164 = _match(r"E164:\s*([+0-9]+)")
    international_number = _match(r"International:\s*([0-9]+)")
    country = _match(r"Country:\s*(.+)")

    scanner_results_val = _match(r"(\d+)\s+scanner\(s\)\s+succeeded")
    try:
        scanner_results = int(scanner_results_val) if scanner_results_val is not None else 0
    except ValueError:
        scanner_results = 0

    phone_value = e164 or indicator
    valid_format = bool(e164)

    return {
        "phone": phone_value,
        "country": country,
        "valid_format": valid_format,
        "local_number": local_number,
        "international_number": international_number,
        "scanner_results": scanner_results,
    }


def analyze_phone(phone_number: str) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """Analyze a phone number using PhoneInfoga via subprocess.

    Returns (analysis_dict, errors_list).
    """
    errors: List[Dict[str, str]] = []

    # Build command, allowing a custom PhoneInfoga path via env var.
    # Example override on Windows PowerShell:
    #   $env:PHONEINFOGA_PATH = 'C:\\Tools\\PhoneInfoga\\phoneinfoga.exe'
    cmd = get_phoneinfoga_command() + ["scan", "-n", phone_number]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        errors.append(
            {
                "component": "phoneinfoga",
                "message": (
                    "PhoneInfoga executable not found. Either add it to PATH "
                    f"or set {PHONEINFOGA_ENV_VAR} to its full path."
                ),
            }
        )
        phone_output = None
    except OSError as exc:
        # Handles Windows architecture / compatibility issues (e.g. WinError 216)
        errors.append(
            {
                "component": "phoneinfoga",
                "message": f"PhoneInfoga failed to start: {exc}",
            }
        )
        phone_output = None
    except subprocess.SubprocessError as exc:
        errors.append(
            {
                "component": "phoneinfoga",
                "message": f"PhoneInfoga execution error: {exc}",
            }
        )
        phone_output = None
    else:
        phone_output = {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
        if proc.returncode != 0:
            errors.append(
                {
                    "component": "phoneinfoga",
                    "message": f"PhoneInfoga returned non-zero exit status {proc.returncode}",
                }
            )

    # Build phoneinfoga analysis block with both structured and raw output
    if phone_output is not None and phone_output.get("returncode") == 0 and phone_output.get("stdout"):
        structured = parse_phoneinfoga_output(str(phone_output.get("stdout", "")), phone_number)
        phoneinfoga_block: Dict[str, Any] = {
            "status": "ok",
            "structured": structured,
            "raw_output": phone_output.get("stdout", ""),
            "returncode": phone_output.get("returncode"),
            "stderr": phone_output.get("stderr", ""),
        }
    else:
        # Preserve previous behavior while also exposing raw output when available
        if phone_output is not None:
            phoneinfoga_block = {
                "status": "error",
                "error": "PhoneInfoga did not run successfully",
                "raw_output": phone_output.get("stdout", ""),
                "returncode": phone_output.get("returncode"),
                "stderr": phone_output.get("stderr", ""),
            }
        else:
            phoneinfoga_block = {
                "status": "error",
                "error": "PhoneInfoga did not run successfully",
            }

    analysis = {
        "virustotal": "NA",
        "whois": "NA",
        "domain_metadata": "NA",
        "hosting": "NA",
        "ip_information": "NA",
        "website_analysis": "NA",
        "phoneinfoga": phoneinfoga_block,
        "apk_scan": "NA",
    }

    return analysis, errors


def analyze_apk(file_path: str) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """Analyze an APK by uploading it to VirusTotal.

    Returns (analysis_dict, errors_list).
    """
    errors: List[Dict[str, str]] = []

    vt_result = vt_scan_apk(file_path)
    if vt_result.get("status") == "error":
        errors.append({"component": "apk_scan", "message": vt_result.get("error", "Unknown error")})

    analysis = {
        "virustotal": "NA",
        "whois": "NA",
        "domain_metadata": "NA",
        "hosting": "NA",
        "ip_information": "NA",
        "website_analysis": "NA",
        "phoneinfoga": "NA",
        "apk_scan": vt_result,
    }

    return analysis, errors


def calculate_risk_score(
    user_input: Optional[str],
    input_type: str,
    analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """Compute a heuristic risk score and level for domains/URLs.

    Scoring (additive):
    +3 points → Domain age < 30 days
    +2 points → WHOIS privacy enabled
    +1 point → Suspicious keywords in domain name
    +2 points → Any VirusTotal detections
    +1 point → Newly issued SSL certificate (< 30 days)
    """

    # Default response
    result = {
        "risk_score": 0,
        "risk_level": "Low",
        "reason": ["Risk scoring currently implemented for URLs/domains only"],
    }

    if input_type not in {"url", "domain"} or not user_input:
        return result

    reasons: List[str] = []
    score = 0

    domain_str = user_input.lower()
    if input_type == "url":
        parsed = urlparse(user_input)
        if parsed.hostname:
            domain_str = parsed.hostname.lower()

    # Pull supporting data
    domain_md = analysis.get("domain_metadata") or {}
    vt = analysis.get("virustotal") or {}
    whois_data = analysis.get("whois") or {}

    # Domain age
    age_days = domain_md.get("age_days")
    try:
        if age_days is not None and int(age_days) < 30:
            score += 3
            reasons.append("Domain younger than 30 days")
    except (TypeError, ValueError):
        pass

    # WHOIS privacy detection
    privacy_enabled = False
    if isinstance(whois_data, dict) and whois_data.get("status") == "ok":
        w_resp = whois_data.get("response") or {}
        if isinstance(w_resp, dict):
            for key in ("name", "org", "registrant_name", "registrant_org"):
                val = w_resp.get(key)
                if isinstance(val, str):
                    v = val.lower()
                    if "privacy" in v or "withheld" in v or "redacted" in v:
                        privacy_enabled = True
                        break
    if privacy_enabled:
        score += 2
        reasons.append("Registrant privacy enabled")

    # Suspicious domain keywords
    suspicious_keywords = [
        "bank",
        "card",
        "upgrade",
        "secure",
        "verify",
        "login",
        "account",
    ]
    matched_keywords = [kw for kw in suspicious_keywords if kw in domain_str]
    if matched_keywords:
        score += 1
        reasons.append(f"Suspicious keywords in domain: {', '.join(matched_keywords)}")

    # VirusTotal detections
    vt_stats = None
    if isinstance(vt, dict) and vt.get("status") == "ok":
        try:
            vt_stats = vt["response"]["data"]["attributes"].get("last_analysis_stats")  # type: ignore[index]
        except Exception:
            vt_stats = None

    if isinstance(vt_stats, dict):
        malicious = vt_stats.get("malicious", 0) or 0
        suspicious = vt_stats.get("suspicious", 0) or 0
        try:
            total_hits = int(malicious) + int(suspicious)
        except (TypeError, ValueError):
            total_hits = 0
        if total_hits > 0:
            score += 2
            reasons.append(f"VirusTotal detections reported (malicious={malicious}, suspicious={suspicious})")

    # Newly issued SSL certificate
    ssl_from = domain_md.get("ssl_valid_from")
    ssl_from_dt = _parse_datetime(ssl_from) if ssl_from else None
    if ssl_from_dt is not None:
        age_cert = datetime.now(timezone.utc) - ssl_from_dt
        if age_cert.days < 30:
            score += 1
            reasons.append("Newly issued SSL certificate (< 30 days)")

    # Map score to level
    if score <= 2:
        level = "Low"
    elif 3 <= score <= 5:
        level = "Medium"
    else:
        level = "High"

    if not reasons:
        reasons.append("No notable risky attributes detected under current heuristics")

    return {
        "risk_score": score,
        "risk_level": level,
        "reason": reasons,
    }


def _build_virustotal_summary(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Build a compact summary of VirusTotal detections.

    Extracts last_analysis_stats from the full VT response and returns:
    {
        "malicious": int | "NA",
        "suspicious": int | "NA",
        "engines_checked": int | "NA",
    }
    """

    default_summary: Dict[str, Any] = {
        "malicious": "NA",
        "suspicious": "NA",
        "engines_checked": "NA",
    }

    vt_block = analysis.get("virustotal")
    if not isinstance(vt_block, dict) or vt_block.get("status") != "ok":
        return default_summary

    try:
        attrs = vt_block["response"]["data"]["attributes"]  # type: ignore[index]
        stats = attrs.get("last_analysis_stats") or {}
    except Exception:
        return default_summary

    if not isinstance(stats, dict):
        return default_summary

    def _to_int(value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    malicious = _to_int(stats.get("malicious"))
    suspicious = _to_int(stats.get("suspicious"))
    undetected = _to_int(stats.get("undetected"))
    harmless = _to_int(stats.get("harmless"))

    engines_checked = malicious + suspicious + undetected + harmless

    # If all values are zero and stats looked empty, fall back to NA
    if engines_checked == 0 and not any(stats.get(k) is not None for k in ("malicious", "suspicious", "undetected", "harmless")):
        return default_summary

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "engines_checked": engines_checked,
    }


def resolve_domain_ip(domain: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a domain name to an IP address using DNS.

    Uses a small in-memory cache to avoid repeated lookups.
    Returns (ip_address or None, error_message or None).
    """

    domain = (domain or "").strip()
    if not domain:
        return None, "Empty domain for IP resolution"

    if domain in _domain_ip_cache:
        return _domain_ip_cache[domain], None

    try:
        ip_addr = socket.gethostbyname(domain)
    except OSError as exc:
        return None, f"DNS resolution failed for {domain}: {exc}"

    _domain_ip_cache[domain] = ip_addr
    return ip_addr, None


def get_ip_information(ip_address: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Fetch IP intelligence for an address using ip-api.com.

    Caches results per IP to avoid duplicate HTTP calls.
    On failure, returns (None, error_message).
    """

    ip_address = (ip_address or "").strip()
    if not ip_address:
        return None, "Empty IP address for IP intelligence lookup"

    if ip_address in _ip_info_cache:
        return _ip_info_cache[ip_address], None

    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,isp,org,as,lat,lon,query"

    try:
        resp = requests.get(url, timeout=5)
    except requests.RequestException as exc:
        return None, f"IP intelligence lookup failed: {exc}"

    try:
        data = resp.json()
    except ValueError:
        return None, "IP intelligence service returned non-JSON response"

    if not isinstance(data, dict):
        return None, "Unexpected IP intelligence response format"

    if data.get("status") != "success":
        msg = data.get("message") or "Unknown error from IP intelligence service"
        return None, f"IP intelligence service error: {msg}"

    # Map ip-api response into our canonical structure, defaulting missing
    # values to "NA" so the JSON is always well-formed for the AI agent.
    ip_info: Dict[str, Any] = {
        "ip_address": data.get("query") or ip_address,
        "country": data.get("country") or "NA",
        "region": data.get("regionName") or "NA",
        "city": data.get("city") or "NA",
        "isp": data.get("isp") or "NA",
        "organization": data.get("org") or "NA",
        "asn": data.get("as") or "NA",
        "latitude": data.get("lat") if data.get("lat") is not None else "NA",
        "longitude": data.get("lon") if data.get("lon") is not None else "NA",
    }

    _ip_info_cache[ip_address] = ip_info
    return ip_info, None


def get_hosting_provider(ip_info: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Derive hosting provider details from IP intelligence data.

    Expects the structure produced by get_ip_information and reuses it
    instead of performing another external lookup.
    """

    if not isinstance(ip_info, dict) or not ip_info.get("ip_address"):
        return None, "No IP information available for hosting provider detection"

    hosting_provider = ip_info.get("organization") or ip_info.get("isp") or "NA"

    hosting = {
        "hosting_provider": hosting_provider,
        "asn": ip_info.get("asn") or "NA",
        "organization": ip_info.get("organization") or "NA",
        "isp": ip_info.get("isp") or "NA",
    }

    return hosting, None


def build_base_response(user_input: Optional[str], input_type: str) -> Dict[str, Any]:
    """Create a base response structure with NA defaults for analysis fields."""
    return {
        "input": user_input,
        "type": input_type,
        "virustotal_summary": {
            "malicious": "NA",
            "suspicious": "NA",
            "engines_checked": "NA",
        },
        "analysis": {
            "virustotal": "NA",
            "whois": "NA",
            "domain_metadata": "NA",
            "hosting": "NA",
            "ip_information": "NA",
            "website_analysis": "NA",
            "phoneinfoga": "NA",
            "apk_scan": "NA",
        },
        "risk_assessment": {
            "risk_score": 0,
            "risk_level": "Low",
            "reason": ["Not evaluated"],
        },
        "errors": [],
    }


def main() -> None:
    # No extra console output: only emit JSON to stdout.
    if len(sys.argv) < 2:
        result = build_base_response(None, "unknown")
        result["errors"].append(
            {
                "component": "main",
                "message": "No input provided. Usage: python threat_analyzer.py <input>",
            }
        )
        print(json.dumps(result, ensure_ascii=False))
        return

    user_input = sys.argv[1]
    input_type = detect_input(user_input)

    result = build_base_response(user_input, input_type)

    if input_type == "url" or input_type == "domain":
        analysis, errors = analyze_url(user_input, input_type)
    elif input_type == "phone":
        analysis, errors = analyze_phone(user_input)
    elif input_type == "apk":
        analysis, errors = analyze_apk(user_input)
    else:
        analysis = result["analysis"]
        errors = [
            {
                "component": "detection",
                "message": "Unsupported or unrecognized input type",
            }
        ]

    result["analysis"] = analysis
    result["errors"].extend(errors)

    # Risk assessment (primarily for URL/domain inputs)
    result["risk_assessment"] = calculate_risk_score(user_input, input_type, result["analysis"])

    # Compact VirusTotal detection summary for AI consumption
    result["virustotal_summary"] = _build_virustotal_summary(result["analysis"])

    # Final JSON output only
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
