from fastapi import FastAPI, UploadFile, File
from parser.email_parser import parse_eml_bytes

app = FastAPI(
    title="Email Threat Detection Platform",
    description="Cybersecurity API for analyzing suspicious emails",
    version="1.0.0",
)


@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "Email Threat Detection API is running"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }


@app.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    raw_bytes = await file.read()

    result = parse_eml_bytes(raw_bytes)

    return {
        "filename": file.filename,
        "result": result
    }