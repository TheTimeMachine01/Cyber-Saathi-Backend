# Cyber-Saathi Backend

This is the backend for the Cyber-Saathi project, providing incident reporting, case management, and automated cyber threat analysis.

## Architecture

- **Convex**: Serverless database and functions (located in `/convex`).
- **Clerk**: Authentication and user identity management.
- **Analysis Microservice**: A FastAPI-based service (located in `/automation`) that runs OSINT tools like PhoneInfoga and OCR-based threat analysis.

## Project Structure

- `convex/`: Convex schema, mutations, and queries.
- `automation/`: 
  - `analysis_service.py`: FastAPI bridge between frontend and automation scripts.
  - `scripts/`: Python OSINT and OCR automation scripts.
  - `Dockerfile`: Deployment configuration for Render.com.
- `.github/workflows/`: Automated deployment to Render.

## Setup & Local Development

### Convex Backend

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the Convex development server:
   ```bash
   npx convex dev
   ```

### Automation Service (FastAPI)

1. Navigate to the automation folder:
   ```bash
   cd automation
   ```

2. Run the setup script (Linux):
   ```bash
   chmod +x setup_linux.sh
   ./setup_linux.sh
   ```

3. Start the service:
   ```bash
   export CONVEX_URL=your_convex_url
   python3 analysis_service.py
   ```

## Deployment

### Render.com
The analysis service is configured for deployment on Render.com using the provided `Dockerfile`. Use the GitHub Action in `.github/workflows/deploy-analysis.yml` to automate deployments.

### Environment Variables
Ensure the following are set in your deployment environment:
- `CONVEX_URL`: Your Convex application URL.
- `VT_API_KEY`: (Optional) VirusTotal API key for advanced analysis.
- `CLERK_JWT_ISSUER_DOMAIN`: Your Clerk issuer domain for authentication.

## License
ISC
