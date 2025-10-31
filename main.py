import uuid
import pandas as pd
import uvicorn
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import bcrypt
import logging
import os
import ssl


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain('security/cert.pem', keyfile='security/key.pem')

logger = logging.getLogger(__name__)
USERS = "users.csv"
ADMIN_USERNAME = "admin"

templates = Jinja2Templates(directory="templates")
SESSION_TTL = timedelta(minutes=3)
sessions = {}
white_urls = ["/", "/login", "/logout", "/register"]

def load_users():
    try:
        return pd.read_csv(USERS)
    except FileNotFoundError:
        return pd.DataFrame(columns=["username", "password", "role"])

def save_user(username, password, role="user"):
    df = load_users()
    username = username.strip()
    if username in df["username"].astype(str).str.strip().values:
        return False
    hashed_pw = bcrypt.hashpw(password.strip().encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    new_user = pd.DataFrame([[username, hashed_pw, role]], columns=["username", "password", "role"])
    df = pd.concat([df, new_user], ignore_index=True)
    df.to_csv(USERS, index=False)
    logger.info(f"user {username} saved successfully!")
    return True

def check_user(username, password):
    df = load_users()
    df["username"] = df["username"].astype(str).str.strip()
    df["password"] = df["password"].astype(str).str.strip()
    user_row = df[df["username"] == username.strip()]
    if user_row.empty:
        return False
    stored_hash = user_row.iloc[0]["password"]
    if bcrypt.checkpw(password.strip().encode("utf-8"), stored_hash.encode("utf-8")):
        return user_row.iloc[0]["role"]
    return False

def get_session(request: Request):
    """Return session dict or None if invalid/expired."""
    session_id = request.cookies.get("session_id")
    session = sessions.get(session_id)
    if not session:
        return None
    if session["expires"] < datetime.now():
        # expired, remove it
        del sessions[session_id]
        return None
    return session


@app.get("/", response_class=HTMLResponse)
def get_start_page(request: Request):
    session = get_session(request)
    if session:
        ttl_seconds = int((session["expires"] - datetime.now()).total_seconds())
        return templates.TemplateResponse(
            "main.html",
            {"request": request, "username": session["username"], "role": session["role"], "ttl": ttl_seconds}
        )
    return RedirectResponse("/login")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    role = check_user(username, password)
    if role:
        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            "username": username,
            "role": role,
            "expires": datetime.now() + SESSION_TTL
        }
        logger.info(f"username:{username}, role:{role}, session expires {datetime.now() + SESSION_TTL}")
        response = RedirectResponse("/", status_code=302)
        response.set_cookie("session_id", session_id, httponly=True, secure=True, samesite="Strict")
        return response
    logger.warning("Incorrect user or passwd provided")
    return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный логин или пароль"})

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login")
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    return templates.TemplateResponse("register.html", {"request": request, "error": None})

@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login")
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    if save_user(username, password, role="user"):
        logger.info(f"Admin {session['username']} registered new user: {username}")
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request, "error": "Пользователь уже существует"})

@app.get("/logout")
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in sessions:
        del sessions[session_id]
    response = RedirectResponse("/login")
    response.delete_cookie("session_id")
    return response

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login")
    if session["role"] != "admin":
        logger.warning(f"Attempt to access admin page from user {session['username']}")
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    df = load_users()
    users = df.to_dict(orient="records")
    logger.info(f"admin panel used by {session['username']}")
    return templates.TemplateResponse("admin.html", {"request": request, "users": users})

@app.get("/refresh_session")
def refresh_session(request: Request):
    session_id = request.cookies.get("session_id")
    session = sessions.get(session_id)
    if session:
        session["expires"] = datetime.now() + SESSION_TTL
        logger.info(f"session {session['username']} extended to {session['expires']}")
        return {"status": "ok", "new_expire": str(session["expires"])}
    raise HTTPException(status_code=401, detail="Сессия не найдена")


@app.exception_handler(401)
async def custom_401_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse(
        "401.html", {"request": request, "detail": "Custom 401 Not Session Page"}, status_code=401
    )

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse(
        "404.html", {"request": request, "detail": "Custom 404 Not Found Page"}, status_code=404
    )

@app.exception_handler(403)
async def custom_403_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse(
        "403.html", {"request": request, "detail": "Custom 403 Forbidden Page"}, status_code=403
    )


def init_users_file():
    if not os.path.exists(USERS):
        admin_password = input("enter admin passwd:")
        hashed_pw = bcrypt.hashpw(admin_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        df = pd.DataFrame([[ADMIN_USERNAME, hashed_pw, "admin"]], columns=["username", "password", "role"])
        df.to_csv(USERS, index=False)
        logger.info(f"Created file {USERS} with admin (username='{ADMIN_USERNAME}')")

init_users_file()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=443,
        ssl_certfile='security/cert.pem',
        ssl_keyfile='security/key.pem',
        log_config="logs/log_config.yaml"
    )
