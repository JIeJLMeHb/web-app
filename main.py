import uuid
import pandas as pd
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import bcrypt
import logging
import os


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
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
        return pd.DataFrame(columns=["username", "password"])

def save_user(username, password):
    df = load_users()
    username = username.strip()
    if username in df["username"].astype(str).str.strip().values:
        return False
    hashed_pw = bcrypt.hashpw(password.strip().encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    new_user = pd.DataFrame([[username, hashed_pw]], columns=["username", "password"])
    df = pd.concat([df, new_user], ignore_index=True)
    df.to_csv(USERS, index=False)
    return True

def check_user(username, password):
    df = load_users()
    df["username"] = df["username"].astype(str).str.strip()
    df["password"] = df["password"].astype(str).str.strip()
    user_row = df[df["username"] == username.strip()]
    if user_row.empty:
        return False
    stored_hash = user_row.iloc[0]["password"]
    return bcrypt.checkpw(password.strip().encode("utf-8"), stored_hash.encode("utf-8"))

@app.get("/", response_class=HTMLResponse)
def get_start_page(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in sessions and sessions[session_id]["expires"] > datetime.now():
        username = sessions[session_id]["username"]
        return templates.TemplateResponse("main.html", {"request": request, "username": username})
    return RedirectResponse("/login")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if check_user(username, password):
        session_id = str(uuid.uuid4())
        sessions[session_id] = {"username": username, "expires": datetime.now() + SESSION_TTL}
        logger.info(f"username:{username}, session expires {datetime.now() + SESSION_TTL}")
        response = RedirectResponse("/", status_code=302)
        response.set_cookie("session_id", session_id)
        return response
    logger.warning("Incorrect user or passwd provided")
    return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный логин или пароль"})


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        return RedirectResponse("/login")
    if sessions[session_id]["username"] != ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    return templates.TemplateResponse("register.html", {"request": request, "error": None})

@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        return RedirectResponse("/login")
    if sessions[session_id]["username"] != ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    if save_user(username, password):
        logger.info(f"Admin {sessions[session_id]['username']} registered new user: {username}")
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request, "error": "Пользователь уже существует"})


@app.get("/logout")
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        del sessions[session_id]
    response = RedirectResponse("/login")
    response.delete_cookie("session_id")
    return response

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse(
        "404.html", {"request": request, "detail": "Custom 404 Not Found Page"}, status_code=404
    )


def init_users_file():
    if not os.path.exists(USERS):
        admin_password = input("enter admin passwd:")
        hashed_pw = bcrypt.hashpw(admin_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        df = pd.DataFrame([[ADMIN_USERNAME, hashed_pw]], columns=["username", "password"])
        df.to_csv(USERS, index=False)
        logger.info(f"Created file {USERS} with admin (username='{ADMIN_USERNAME}')")

init_users_file()
