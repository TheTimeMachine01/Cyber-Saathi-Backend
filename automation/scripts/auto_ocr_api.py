import easyocr
import cv2
import re
import json
import sys

# -------- READ IMAGE PATH FROM ARGUMENT -------- #

if len(sys.argv) < 2:
    print("Usage: python auto_ocr_api.py <image>")
    sys.exit()

image_path = sys.argv[1]

print("\nScanning Image:", image_path)

# -------- PREPROCESS IMAGE -------- #

img = cv2.imread(image_path)

if img is None:
    print("Error: Image not found")
    sys.exit()

gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

# Improve OCR accuracy
gray = cv2.GaussianBlur(gray,(3,3),0)

# -------- OCR -------- #

reader = easyocr.Reader(['en'], gpu=False)
result = reader.readtext(gray, detail=0)

text = " ".join(result)

# -------- TEXT CLEANUP -------- #

text = re.sub(r'\s+', ' ', text)
text_lower = text.lower()

# -------- REGEX DETECTORS -------- #

phone_pattern = r'\b[6-9]\d{9}\b'

upi_pattern = r'\b[a-zA-Z0-9.\-_]{2,}@(okaxis|okhdfc|oksbi|okicici|ybl|ibl|paytm|apl)\b'

email_pattern = r'\b[\w.-]+@[\w.-]+\.\w+\b'

url_pattern = r'https?://\S+|www\.\S+'

telegram_pattern = r'@[\w\d_]{5,}'

insta_pattern = r'(?<!\w)@[A-Za-z0-9._]{3,30}'

transaction_pattern = r'\bTXN[\w\d]+\b|\bUTR[\w\d]+\b'

bank_pattern = r'\b\d{11,18}\b'

ifsc_pattern = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'

ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

pan_pattern = r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'

aadhaar_pattern = r'\b\d{4}\s?\d{4}\s?\d{4}\b'

vehicle_pattern = r'\b[A-Z]{2}\d{2}[A-Z]{2}\d{4}\b'

crypto_pattern = r'\b(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'

card_pattern = r'\b(?:\d[ -]*?){13,16}\b'

otp_pattern = r'\b\d{4,6}\b'

imei_pattern = r'\b\d{15}\b'

mac_pattern = r'\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b'

# -------- FIND DATA -------- #

phones = re.findall(phone_pattern, text)

upi = re.findall(upi_pattern, text)

emails = re.findall(email_pattern, text)

urls = re.findall(url_pattern, text)

telegram = re.findall(telegram_pattern, text)

insta = re.findall(insta_pattern, text)

transaction = re.findall(transaction_pattern, text)

bank = re.findall(bank_pattern, text)

ifsc = re.findall(ifsc_pattern, text)

ip = re.findall(ip_pattern, text)

pan = re.findall(pan_pattern, text)

aadhaar = re.findall(aadhaar_pattern, text)

vehicle = re.findall(vehicle_pattern, text)

crypto = re.findall(crypto_pattern, text)

card = re.findall(card_pattern, text)

otp = re.findall(otp_pattern, text)

imei = re.findall(imei_pattern, text)

mac = re.findall(mac_pattern, text)

# -------- REMOVE DUPLICATES -------- #

def unique(data):
    return list(set(data))

phones = unique(phones)
upi = unique(upi)
emails = unique(emails)
urls = unique(urls)
telegram = unique(telegram)
insta = unique(insta)
transaction = unique(transaction)
bank = unique(bank)
ifsc = unique(ifsc)
ip = unique(ip)
pan = unique(pan)
aadhaar = unique(aadhaar)
vehicle = unique(vehicle)
crypto = unique(crypto)
card = unique(card)
otp = unique(otp)
imei = unique(imei)
mac = unique(mac)

# -------- CHAT APP DETECTION -------- #

app = "NA"

if "whatsapp" in text_lower or "last seen" in text_lower or "typing" in text_lower:
    app = "WhatsApp"

elif "telegram" in text_lower:
    app = "Telegram"

elif "instagram" in text_lower:
    app = "Instagram"

elif "messenger" in text_lower:
    app = "Facebook Messenger"

# -------- HANDLE EMPTY VALUES -------- #

def clean(value):
    return value if value else ["NA"]

# -------- JSON OUTPUT -------- #

data = {

"image_name": image_path,

"detected_app": app,

"phone_numbers": clean(phones),

"upi_ids": clean(upi),

"emails": clean(emails),

"urls": clean(urls),

"telegram_ids": clean(telegram),

"instagram_ids": clean(insta),

"transaction_ids": clean(transaction),

"bank_accounts": clean(bank),

"ifsc_codes": clean(ifsc),

"crypto_wallets": clean(crypto),

"ip_addresses": clean(ip),

"pan_numbers": clean(pan),

"aadhaar_numbers": clean(aadhaar),

"vehicle_numbers": clean(vehicle),

"card_numbers": clean(card),

"otp_codes": clean(otp),

"imei_numbers": clean(imei),

"mac_addresses": clean(mac)

}

print("\nOCR JSON RESULT\n")

print(json.dumps(data, indent=4))