import os
import uuid
import aiofiles
import logging
import sys
from typing import Annotated, Any, Optional
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request, Response, Form, Depends, HTTPException, UploadFile, File
from fastapi.responses import Response as FastApiResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logger = logging.getLogger("file_manager")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = logging.FileHandler(os.path.join(LOG_DIR, "app.log"))
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

app = FastAPI(title="Security App")

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "default_secret_key_123"),
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Internal Server Error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "We are sorry, something went wrong."}
    )

STORAGE_DIR = "storage"
MAX_FILE_SIZE = 2 * 1024 * 1024

if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
cipher_suite = Fernet(ENCRYPTION_KEY.encode()) if ENCRYPTION_KEY else None

users = [
    {"username": "admin", "role": "admin"},
    {"username": "alice", "role": "user"},
    {"username": "bob", "role": "user"},
]

files_db = []

@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Any:
    response: Response = await call_next(request)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com;"
    )
    response.headers["Content-Security-Policy"] = csp
    return response

def get_current_user(request: Request) -> Optional[dict]:
    username = request.session.get("name")
    if not username:
        return None
    return next((u for u in users if u["username"] == username), None)

@app.get("/cause_error")
async def cause_error():
    raise RuntimeError("Deliberate error for logging test")

@app.post("/login")
async def login(request: Request, username: str = Form(...)):
    name = username.lower().strip()
    user_exists = any(u["username"] == name for u in users)
    
    if not user_exists:
        logger.warning(f"Security Audit: Failed login attempt for username: {name}")
        raise HTTPException(status_code=400, detail="Invalid username")
    
    logger.info(f"User {name} logged in successfully")
    request.session["name"] = name
    return {"message": f"Logged in as {name}"}

@app.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    encrypt: bool = False,
    user: Annotated[dict, Depends(get_current_user)] = None
):
    if not user:
        logger.warning("Security Audit: Unauthorized upload attempt")
        raise HTTPException(status_code=403, detail="Unauthorized")

    content = await file.read()
    
    if len(content) > MAX_FILE_SIZE:
        logger.warning(f"User {user['username']} tried to upload a file exceeding size limit")
        raise HTTPException(status_code=413, detail="File too large")

    if encrypt:
        if not cipher_suite:
            logger.error("Encryption requested but key not configured")
            raise HTTPException(status_code=500, detail="Encryption key not configured")
        content = cipher_suite.encrypt(content)

    file_uuid = str(uuid.uuid4())
    physical_path = os.path.join(STORAGE_DIR, f"{file_uuid}.bin")

    async with aiofiles.open(physical_path, "wb") as buffer:
        await buffer.write(content)

    new_file = {
        "id": len(files_db) + 1,
        "filename": file.filename,
        "owner": user["username"],
        "path": physical_path,
        "is_encrypted": encrypt
    }
    files_db.append(new_file)
    
    logger.info(f"File {file.filename} uploaded by {user['username']} (ID: {new_file['id']})")
    return {"message": "Uploaded", "file_id": new_file["id"], "encrypted": encrypt}

@app.get("/files/{file_id}/download")
async def download_file(
    file_id: int, 
    user: Annotated[dict, Depends(get_current_user)] = None
):
    if not user:
        logger.warning(f"Security Audit: Unauthorized download attempt for file_id {file_id}")
        raise HTTPException(status_code=403, detail="Unauthorized")

    file_data = next((f for f in files_db if f["id"] == file_id), None)
    if not file_data or not os.path.exists(file_data["path"]):
        logger.info(f"User {user['username']} requested non-existent file {file_id}")
        raise HTTPException(status_code=404, detail="File not found")

    if user["role"] != "admin" and file_data["owner"] != user["username"]:
        logger.warning(f"Security Audit: Access denied for user {user['username']} to file {file_id}")
        raise HTTPException(status_code=403, detail="Access denied")

    async with aiofiles.open(file_data["path"], "rb") as f:
        content = await f.read()

    if file_data.get("is_encrypted"):
        try:
            content = cipher_suite.decrypt(content)
        except Exception as e:
            logger.error(f"Decryption failed for file {file_id}: {e}")
            raise HTTPException(status_code=500, detail="Decryption failed")

    logger.info(f"User {user['username']} downloaded file {file_data['filename']}")
    return FastApiResponse(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={file_data['filename']}"}
    )

@app.get("/logout")
async def logout(request: Request):
    username = request.session.get("name")
    logger.info(f"User {username} logged out")
    request.session.clear()
    return {"message": "Logged out"}