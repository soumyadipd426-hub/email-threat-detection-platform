from fastapi import FastAPI, UploadFile, File
from parser.email_parser import parse_eml_bytes
from analysis.header_analyzer import parse_email_headers, detect_mismatches

app = FastAPI(
    title="Email Threat Detection Platform",
    description="Email analysis API",
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
    # Read uploaded .eml file
    raw_bytes = await file.read()

    # -------------------------
    # 1. Email Parser
    # -------------------------
    parsed_email = parse_eml_bytes(raw_bytes)

    # -------------------------
    # 2. Header Analysis
    # -------------------------
    header_result = parse_email_headers(raw_bytes)

    # -------------------------
    # 3. Header Mismatch Detection
    # -------------------------
    mismatches = detect_mismatches(
        header_result.identity,
        header_result.authentication
    )

    # Convert header dataclass to JSON-safe dictionary
    header_dict = header_result.to_dict()

    # -------------------------
    # Final response
    # -------------------------
    return {
        "filename": file.filename,

        "parser": parsed_email,

        "header_analysis": header_dict,

        "header_mismatches": mismatches
    }