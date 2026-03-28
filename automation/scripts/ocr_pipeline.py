import easyocr
import re
import subprocess
import json
import sys


def log(message: str) -> None:
	"""Print log messages to stderr to keep stdout clean JSON."""

	print(message, file=sys.stderr)


def run_threat_analysis(indicator: str) -> dict:
	"""Run threat_analyzer.py for a single indicator and return its JSON.

	Never raises on failure; always returns a JSON-serializable dict.
	"""

	log(f"[ANALYZER] Running threat analysis for: {indicator}")

	try:
		result = subprocess.run(
			[sys.executable, "threat_analyzer.py", indicator],
			capture_output=True,
			text=True,
			timeout=300,
		)
	except Exception as exc:  # subprocess.TimeoutExpired, OSError, etc.
		log(f"[ANALYZER] Failed for {indicator}: {exc}")
		return {
			"indicator": indicator,
			"error": "analysis execution failed",
			"details": str(exc),
		}

	if not result.stdout:
		log(f"[ANALYZER] No output from threat_analyzer for: {indicator}")
		return {
			"indicator": indicator,
			"error": "no output from threat_analyzer",
			"returncode": result.returncode,
			"stderr": result.stderr,
		}

	try:
		parsed = json.loads(result.stdout)
		log(f"[ANALYZER] Completed for: {indicator}")
		return {
			"indicator": indicator,
			"analysis": parsed,
		}
	except json.JSONDecodeError:
		log(f"[ANALYZER] JSON parse failed for: {indicator}")
		return {
			"indicator": indicator,
			"error": "analysis returned invalid JSON",
			"raw_output": result.stdout,
			"returncode": result.returncode,
			"stderr": result.stderr,
		}



def normalize_phone(phone: str) -> str:
	"""Normalize Indian phone numbers to international format.

	If the phone number is a 10-digit Indian mobile (starts with 6-9)
	and does not already include a country code, convert it to
	+91XXXXXXXXXX so PhoneInfoga can correctly detect India.
	"""

	phone = phone.strip()
	if re.fullmatch(r"[6-9]\d{9}", phone):
		return "+91" + phone
	return phone


def normalize_domain(domain: str) -> str:
	"""Normalize common OCR domain suffix mistakes.

	Examples:
	- .acin  -> .ac.in
	- .coin  -> .co.in
	- .comn -> .com
	- .oring -> .org
	- .coim -> .co.in
	"""

	domain = domain.strip()
	lower = domain.lower()
	replacements = {
		".acin": ".ac.in",
		".coin": ".co.in",
		".comn": ".com",
		".oring": ".org",
		".coim": ".co.in",
	}

	for wrong, correct in replacements.items():
		if lower.endswith(wrong):
			# Replace only the suffix, preserve the leading part as-is
			return domain[: -len(wrong)] + correct

	return domain


def extract_indicators(text: str) -> dict:
	"""Extract indicators from OCR text.

	Returns raw (non-cleaned) lists for each type.
	"""

	# Phone numbers: Indian-style 10-digit mobile numbers starting 6-9
	phone_pattern = r"\b[6-9]\d{9}\b"

	# URLs with protocol or www
	url_pattern = r"https?://\S+|www\.\S+"

	# Domain-like strings (e.g., cardupgrade.cc) that are not clearly URLs or emails
	domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

	# APK filenames
	apk_pattern = r"\b[\w.-]+\.apk\b"

	phones = list(set(re.findall(phone_pattern, text)))
	urls = list(set(re.findall(url_pattern, text)))

	# Domains: all domain-like tokens, then drop ones that appear inside detected URLs
	all_domains = list(set(re.findall(domain_pattern, text)))
	domains: list[str] = []
	for d in all_domains:
		# Skip if part of a URL we've already captured
		if any(d in u for u in urls):
			continue
		# Skip obvious emails (should not contain '@', but be safe)
		if "@" in d:
			continue
		domains.append(d)

	apks = list(set(re.findall(apk_pattern, text)))

	return {
		"phones": phones,
		"urls": urls,
		"domains": domains,
		"apks": apks,
	}


def clean_list(values):
	"""Return ["NA"] if list is empty, otherwise the list itself."""

	return values if values else ["NA"]


def main() -> None:
	# -------- READ IMAGE PATH FROM ARGUMENT -------- #

	if len(sys.argv) < 2:
		print("Usage: python ocr_pipeline.py <image>", file=sys.stderr)
		sys.exit(1)

	image_path = sys.argv[1]

	log(f"[OCR] Scanning Image: {image_path}")

	# -------- OCR -------- #

	reader = easyocr.Reader(["en"], gpu=False)
	result = reader.readtext(image_path, detail=0)

	text = " ".join(result) if result else ""

	log("[OCR] Extracting indicators...")

	indicators = extract_indicators(text)

	phones_raw = indicators["phones"]
	urls = indicators["urls"]
	domains_raw = indicators["domains"]
	apks = indicators["apks"]

	# -------- NORMALIZATION STEP (phones & domains) -------- #

	# Normalize Indian mobile numbers to +91 format where applicable
	phones = [normalize_phone(p) for p in phones_raw]

	# Normalize common OCR domain suffix mistakes
	domains = [normalize_domain(d) for d in domains_raw]

	for p in phones:
		log(f"[OCR] Found phone: {p}")
	for u in urls:
		log(f"[OCR] Found URL: {u}")
	for d in domains:
		log(f"[OCR] Found domain: {d}")
	for a in apks:
		log(f"[OCR] Found APK: {a}")

	# -------- RUN THREAT ANALYZER (DEDUPED) -------- #

	analysis_results = []
	seen = set()

	for indicator in phones + urls + domains + apks:
		if indicator in seen:
			continue
		seen.add(indicator)

		log("[ANALYZER] Running threat analysis...")
		result = run_threat_analysis(indicator)
		analysis_results.append(result)

	if not analysis_results:
		analysis_results_output: object = "NA"
	else:
		analysis_results_output = analysis_results

	# -------- FINAL JSON OUTPUT -------- #

	output = {
		"image": image_path,
		"extracted_indicators": {
			"phones": clean_list(phones),
			"urls": clean_list(urls),
			"domains": clean_list(domains),
			"apks": clean_list(apks),
		},
		"analysis_results": analysis_results_output,
	}

	print(json.dumps(output, indent=4))


if __name__ == "__main__":
	main()