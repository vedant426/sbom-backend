from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import zipfile
import json
import os
import shutil

# --- DATABASE SETUP ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Create the layout for a User account
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)

# Generate the database tables
Base.metadata.create_all(bind=engine)

# --- FASTAPI APP SETUP ---
app = FastAPI()
@app.get("/")
async def root():
    return {"message": "SBOM Guardian Backend is Live!"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    
    with open(file_location, "wb+") as file_object:
        shutil.copyfileobj(file.file, file_object)

    sbom_result = []

    with zipfile.ZipFile(file_location, 'r') as zip_ref:
        for item in zip_ref.namelist():
            if item.endswith("package.json"):
                with zip_ref.open(item) as f:
                    data = json.load(f)
                    dependencies = data.get("dependencies", {})
                    
                    for pkg, ver in dependencies.items():
                        clean_ver = ver.replace('^', '').replace('~', '')
                        anomaly = "Red Flag: Vulnerable Version" if VULN_DB.get(pkg) == clean_ver else "Clean"
                        
                        sbom_result.append({
                            "library": pkg,
                            "version": clean_ver,
                            "anomaly": anomaly
                        })
    
    os.remove(file_location)
    return {"status": "success", "sbom": sbom_result}