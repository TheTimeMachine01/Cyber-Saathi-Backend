import os
import subprocess
import json
import httpx
import logging
import sys
from fastapi import FastAPI, UploadFile, File, HTTPException, Header, Form
from typing import Optional
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("analysis-service")

app = FastAPI(title="Cyber-Saathi Analysis Service")

# --- Configuration ---
# Use the convex URL from environment or a default for local testing
CONVEX_URL = os.getenv("CONVEX_URL")
SCRIPTS_DIR = Path(__file__).parent / "scripts"

@app.get("/health")
async def health_check():
    return {"status": "ok", "scripts_dir": str(SCRIPTS_DIR)}

@app.post("/analyze")
async def analyze_incident(
    file: Optional[UploadFile] = File(None),
    indicator: Optional[str] = Form(None),
    mode: str = Form("automation"),
    authorization: Optional[str] = Header(None)
):
    """
    Receives an image (for automation) or a string indicator (for manual),
    runs the investigation pipeline, and returns the results.
    """
    temp_path = None
    
    try:
        # 1. Determine Input
        if mode in ["automation", "auto"]:
            if not file:
                raise HTTPException(status_code=400, detail="File is required for automation mode")
            
            # Save uploaded file temporarily
            temp_path = Path(f"temp_{file.filename}")
            with open(temp_path, "wb") as buffer:
                buffer.write(await file.read())
            
            target = str(temp_path)
            cmd_mode = "auto"
        else:
            if not indicator:
                raise HTTPException(status_code=400, detail="Indicator is required for manual mode")
            target = indicator
            cmd_mode = "manual"

        # 2. Execute the investigation script
        logger.info(f"Running investigation: mode={cmd_mode}, target={target}")
        
        # Ensure we run from the scripts directory so relative imports work
        result = subprocess.run(
            [sys.executable, "investigation_mode.py", cmd_mode, target],
            capture_output=True,
            text=True,
            cwd=str(SCRIPTS_DIR)
        )
        
        if result.returncode != 0:
            logger.error(f"Script failed: {result.stderr}")
            raise HTTPException(status_code=500, detail=f"Analysis script error: {result.stderr}")

        try:
            analysis_results = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse JSON: {result.stdout}")
            raise HTTPException(status_code=500, detail="Analysis produced invalid JSON output")

        # 3. Sync with Convex Backend if URL and Auth are provided
        if CONVEX_URL and authorization:
            try:
                async with httpx.AsyncClient() as client:
                    convex_resp = await client.post(
                        f"{CONVEX_URL}/api/analysis",
                        json={
                            "indicator": indicator or (file.filename if file else "Media File"),
                            "mode": mode,
                            "results": analysis_results
                        },
                        headers={"Authorization": authorization}
                    )
                    logger.info(f"Convex sync status: {convex_resp.status_code}")
            except Exception as e:
                logger.warning(f"Failed to sync with Convex: {e}")

        return {"success": True, "results": analysis_results}

    except Exception as e:
        logger.exception("Error during analysis")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up temp file
        if temp_path and temp_path.exists():
            temp_path.unlink()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
