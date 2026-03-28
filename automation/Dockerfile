# Use a slim Python image for efficiency
FROM python:3.10-slim

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install system-level dependencies for OCR, OpenCV, and PhoneInfoga
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libgl1-mesa-glx \
    libglib2.0-0 \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install PhoneInfoga (Linux binary) directly into /usr/local/bin
RUN curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/install.sh | bash \
    && mv ./phoneinfoga /usr/local/bin/phoneinfoga \
    && chmod +x /usr/local/bin/phoneinfoga

# Set the working directory
WORKDIR /app

# Copy requirements and install Python dependencies
# Use --no-cache-dir to keep the image small
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the automation folder contents
COPY . .

# Expose the port FastAPI will run on
EXPOSE 8000

# Command to run the application
# We use --host 0.0.0.0 for external access and $PORT for Render compatibility
CMD ["sh", "-c", "uvicorn analysis_service:app --host 0.0.0.0 --port ${PORT:-8000}"]
