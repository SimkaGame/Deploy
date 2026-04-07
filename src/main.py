import os
import uuid
import filetype
from typing import Annotated, Any, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, Form, Depends, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

app = FastAPI(title="Security App")

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "default_secret_key_123"),
)

STORAGE_DIR = "storage"
MAX_FILE_SIZE = 2 * 1024 * 1024
ALLOWED_MIMES = ["image/jpeg", "image/png"]

if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

users = [
    {"username": "admin", "role": "admin"},
    {"username": "alice", "role": "user"},
    {"username": "bob", "role": "user"},
]

files_db = [
    {"id": 1, "filename": "report_alice.pdf", "owner": "alice", "path": None},
    {"id": 2, "filename": "photo_bob.jpg", "owner": "bob", "path": None},
]

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


@app.post("/login")
async def login(request: Request, username: str = Form(...)):
    name = username.lower().strip()
    if not any(u["username"] == name for u in users):
        raise HTTPException(status_code=400, detail="Invalid username")
    request.session["name"] = name
    return {"message": f"Logged in as {name}"}

@app.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...), 
    user: Annotated[dict, Depends(get_current_user)] = None
):
    if not user:
        raise HTTPException(status_code=403, detail="Unauthorized")

    head = await file.read(2048)
    await file.seek(0)
    kind = filetype.guess(head)
    
    if kind is None or kind.mime not in ALLOWED_MIMES:
        raise HTTPException(status_code=400, detail=f"Uploaded file is not a valid JPEG/PNG image")

    file_uuid = str(uuid.uuid4())
    physical_path = os.path.join(STORAGE_DIR, f"{file_uuid}.bin")

    total_size = 0
    with open(physical_path, "wb") as buffer:
        while True:
            chunk = await file.read(1024 * 512)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > MAX_FILE_SIZE:
                buffer.close()
                os.remove(physical_path)
                raise HTTPException(status_code=413, detail="File too large")
            buffer.write(chunk)

    new_file = {
        "id": len(files_db) + 1,
        "filename": file.filename,
        "owner": user["username"],
        "path": physical_path
    }
    files_db.append(new_file)
    
    return {"message": "Uploaded", "file_id": new_file["id"]}

@app.get("/files/{file_id}/download")
async def download_file(
    file_id: int, 
    user: Annotated[dict, Depends(get_current_user)] = None
):
    if not user:
        raise HTTPException(status_code=403, detail="Unauthorized")

    file_data = next((f for f in files_db if f["id"] == file_id), None)
    if not file_data or not file_data["path"]:
        raise HTTPException(status_code=404, detail="File not found on disk")

    if user["role"] != "admin" and file_data["owner"] != user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")

    return FileResponse(
        path=file_data["path"],
        filename=file_data["filename"],
        content_disposition_type="attachment"
    )

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return {"message": "Logged out"}