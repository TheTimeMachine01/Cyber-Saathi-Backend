import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, Optional, Tuple


def log(message: str) -> None:
    """Print log messages to stderr to keep stdout machine-readable JSON."""

    print(message, file=sys.stderr)


# -------- Input Type Detection -------- #

PHONE_REGEX = re.compile(r"^\+?\d{10,15}$")
IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".bmp", ".webp")


def is_phone(value: str) -> bool:
    return bool(PHONE_REGEX.match(value.strip()))


def is_url(value: str) -> bool:
    v = value.strip().lower()
    return v.startswith("http://") or v.startswith("https://")


def is_apk(value: str) -> bool:
    return value.strip().lower().endswith(".apk")


def is_image(value: str) -> bool:
    return value.strip().lower().endswith(IMAGE_EXTENSIONS)


def is_domain(value: str) -> bool:
    v = value.strip()
    # Basic heuristic: has a dot and no spaces; not clearly a URL or file path.
    return "." in v and not is_url(v) and " " not in v


# -------- Subprocess Helpers -------- #


def run_ocr_pipeline(image_path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Run ocr_pipeline.py for a given image and parse its JSON output.

    Returns (result_dict or None, error_message or None).
    """

    cmd = [sys.executable, "ocr_pipeline.py", image_path]
    log("[MODE] Automation Investigation")
    log("[OCR] Extracting text from screenshot")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except Exception as exc:
        return None, f"Failed to run ocr_pipeline.py: {exc}"

    if not proc.stdout:
        return None, f"ocr_pipeline.py produced no output (returncode={proc.returncode})"

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return None, f"Invalid JSON from ocr_pipeline.py: {exc}"

    return data, None


def run_threat_analyzer(indicator: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Run threat_analyzer.py for a single indicator and parse its JSON.

    Returns (result_dict or None, error_message or None).
    """

    log("[MODE] Manual Investigation")
    log(f"Analyzing indicator: {indicator}")

    cmd = [sys.executable, "threat_analyzer.py", indicator]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except Exception as exc:
        return None, f"Failed to run threat_analyzer.py: {exc}"

    if not proc.stdout:
        return None, f"threat_analyzer.py produced no output (returncode={proc.returncode})"

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return None, f"Invalid JSON from threat_analyzer.py: {exc}"

    return data, None


# -------- Main Mode Handlers -------- #


def handle_automation_mode(image_path: str) -> Dict[str, Any]:
    """Automation mode: screenshot -> OCR -> indicator analysis."""

    if not is_image(image_path):
        return {
            "mode": "automation",
            "error": "Error: Unsupported input",
            "input": image_path,
        }

    if not os.path.isfile(image_path):
        return {
            "mode": "automation",
            "error": "Error: File not found",
            "image": image_path,
        }

    ocr_result, err = run_ocr_pipeline(image_path)
    if err or ocr_result is None:
        return {
            "mode": "automation",
            "error": err or "Unknown OCR error",
            "image": image_path,
        }

    # Wrap the existing OCR pipeline JSON with the mode field.
    result: Dict[str, Any] = {"mode": "automation"}
    result.update(ocr_result)
    return result


def handle_manual_mode(indicator: str) -> Dict[str, Any]:
    """Manual mode: directly investigate a user-provided indicator."""

    value = indicator.strip()

    # Determine type and validate.
    if is_image(value):
        # Images are intended for automation mode via OCR.
        return {
            "mode": "manual",
            "indicator": indicator,
            "error": "Error: Unsupported input",
        }

    if is_apk(value):
        if not os.path.isfile(value):
            return {
                "mode": "manual",
                "indicator": indicator,
                "error": "Error: File not found",
            }
        # Treat as valid APK indicator.
    elif not (is_phone(value) or is_url(value) or is_domain(value)):
        return {
            "mode": "manual",
            "indicator": indicator,
            "error": "Error: Unsupported input",
        }

    analysis, err = run_threat_analyzer(indicator)
    if err or analysis is None:
        return {
            "mode": "manual",
            "indicator": indicator,
            "error": err or "Unknown analysis error",
        }

    # Do not modify JSON returned by threat_analyzer.py; embed it as-is.
    return {
        "mode": "manual",
        "indicator": indicator,
        "analysis": analysis,
    }


def main() -> None:
    if len(sys.argv) < 3:
        out = {
            "error": "Usage: python investigation_mode.py <auto|manual> <input>",
        }
        print(json.dumps(out, ensure_ascii=False))
        return

    mode = sys.argv[1].strip().lower()
    target = sys.argv[2]

    if mode in {"auto", "automation"}:
        result = handle_automation_mode(target)
    elif mode == "manual":
        result = handle_manual_mode(target)
    else:
        result = {
            "error": "Error: Unsupported mode",
            "mode": mode,
            "input": target,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
