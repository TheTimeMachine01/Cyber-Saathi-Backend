#!/bin/bash

echo "🚀 Setting up Cyber-Saathi Analysis Environment (Linux)..."

# 1. Install System Dependencies (Tesseract OCR & OpenCV libs)
echo "📦 Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y tesseract-ocr libgl1-mesa-glx libglib2.0-0 curl git python3-pip python3-venv

# 2. Install PhoneInfoga (Linux Binary)
echo "📥 Downloading PhoneInfoga Linux binary..."
curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/install.sh | bash

# Create bin directory in automation if it doesn't exist
mkdir -p scripts/bin
mv ./phoneinfoga scripts/bin/phoneinfoga
chmod +x scripts/bin/phoneinfoga

echo "✅ PhoneInfoga installed to automation/scripts/bin/phoneinfoga"

# 3. Create Python Virtual Environment (Optional but recommended)
# python3 -m venv venv
# source venv/bin/activate

# 4. Install Python Requirements
echo "🐍 Installing Python requirements..."
pip install -r scripts/requirements.txt
pip install fastapi uvicorn python-multipart httpx easyocr opencv-python-headless python-whois validators requests

echo "🎉 Setup complete! To start the service:"
echo "   export CONVEX_URL=your_convex_url"
echo "   python3 analysis_service.py"
