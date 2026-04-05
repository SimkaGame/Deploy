import os
from typing import Annotated, Any, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, Form, Depends, HTTPException
from starlette.middleware.sessions import SessionMiddleware

# Загружаем SECRET_KEY из .env
load_dotenv()

app = FastAPI(title="Security App")

# Настройка сессий
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "default_secret_key_123"),
)

# --- БАЗА ДАННЫХ (MOCK) ---
users = [
    {"username": "admin", "role": "admin"},
    {"username": "alice", "role": "user"},
    {"username": "bob", "role": "user"},
]

files = [
    {"id": 1, "filename": "report_alice.pdf", "owner": "alice"},
    {"id": 2, "filename": "photo_bob.jpg", "owner": "bob"},
    {"id": 3, "filename": "admin_keys.txt", "owner": "admin"},
]

# --- MIDDLEWARE (БЕЗОПАСНОСТЬ) ---
@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Any:
    response: Response = await call_next(request)
    # Исправленная политика CSP для работы Swagger
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com;"
    )
    response.headers["Content-Security-Policy"] = csp
    return response

# --- ЗАВИСИМОСТИ ---
def get_current_user(request: Request) -> Optional[dict]:
    username = request.session.get("name")
    if not username:
        return None
    return next((u for u in users if u["username"] == username), None)

def check_file_access(
    file_id: int, 
    user: Annotated[Optional[dict], Depends(get_current_user)]
) -> dict:
    if user is None:
        raise HTTPException(status_code=403, detail="Unauthorized")

    file = next((f for f in files if f["id"] == file_id), None)
    
    if file is None:
        raise HTTPException(status_code=404, detail="File not found")

    # RBAC: Админ видит всё. Owner: Юзер видит только своё.
    if user["role"] == "admin" or file["owner"] == user["username"]:
        return file
    
    # IDOR Protection: возвращаем 404, чтобы не "палить" существование чужого файла
    raise HTTPException(status_code=404, detail="File not found")

# --- ЭНДПОИНТЫ ---
@app.post("/login")
async def login(request: Request, username: str = Form(...)):
    name = username.lower().strip()
    if not any(u["username"] == name for u in users):
        raise HTTPException(status_code=400, detail="Invalid username")
    request.session["name"] = name
    return {"message": f"Logged in as {name}"}

@app.get("/files/my")
async def get_my_files(user: Annotated[dict, Depends(get_current_user)]):
    """Список файлов только для текущего пользователя."""
    if user is None:
        raise HTTPException(status_code=403, detail="Unauthorized")
    user_files = [f for f in files if f["owner"] == user["username"]]
    return {"files": user_files}

@app.get("/files/{file_id}")
async def read_file(file: Annotated[dict, Depends(check_file_access)]):
    return {"data": file}

@app.delete("/files/{file_id}")
async def delete_file(file: Annotated[dict, Depends(check_file_access)]):
    files.remove(file)
    return {"message": "Deleted"}

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return {"message": "Logged out"}