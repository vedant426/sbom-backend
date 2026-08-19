from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import zipfile
import json
import os
import shutil

app = FastAPI()

# Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Hardcoded rule list for anomalies
# Expanded database of known vulnerabilities for the hackathon
VULN_DB = {
    "lodash": "4.17.10", 
    "react": "16.0.0",
    "axios": "0.21.1",
    "express": "4.17.1",
    "moment": "2.29.1",
    "jquery": "3.5.0"
}

@app.post("/upload")
async def generate_sbom(file: UploadFile = File(...)):
    file_location = f"temp_{file.filename}"
    
    # Save the uploaded zip file
    with open(file_location, "wb+") as file_object:
        shutil.copyfileobj(file.file, file_object)

    sbom_result = []

    # Unzip and find package.json
    with zipfile.ZipFile(file_location, 'r') as zip_ref:
        for item in zip_ref.namelist():
            if item.endswith("package.json"):
                with zip_ref.open(item) as f:
                    data = json.load(f)
                    dependencies = data.get("dependencies", {})
                    
                    # Build SBOM and flag anomalies
                    for pkg, ver in dependencies.items():
                        clean_ver = ver.replace('^', '').replace('~', '')
                        anomaly = "Red Flag: Vulnerable Version" if VULN_DB.get(pkg) == clean_ver else "Clean"
                        
                        sbom_result.append({
                            "library": pkg,
                            "version": clean_ver,
                            "anomaly": anomaly
                        })
    
    # Delete temp zip file
    os.remove(file_location)
    
    return {"status": "success", "sbom": sbom_result}