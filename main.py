import uuid
import pandas as pd
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

USERS = "users.csv"
templates = Jinja2Templates(directory="templates")
SESSION_TTL = timedelta(minutes=10)
sessions = {}
white_urls = ["/", "/login", "/logout", "/register"]

def load_users():
    try:
        return pd.read_csv(USERS)
    except FileNotFoundError:
        return pd.DataFrame(columns=["username", "password"])

def save_user(username, password):
    df = load_users()
    username, password = username.strip(), password.strip()
    if username in df["username"].astype(str).str.strip().values:
        return False
    new_user = pd.DataFrame([[username, password]], columns=["username", "password"])
    df = pd.concat([df, new_user], ignore_index=True)
    df.to_csv(USERS, index=False)
    return True

def check_user(username, password):
    df = load_users()
    # убираем пробелы и приводим к строке
    df["username"] = df["username"].astype(str).str.strip()
    df["password"] = df["password"].astype(str).str.strip()
    return ((df["username"] == username.strip()) & (df["password"] == password.strip())).any()

# --- Маршруты ---
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
        response = RedirectResponse("/", status_code=302)
        response.set_cookie("session_id", session_id)
        return response
    return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный логин или пароль"})

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})

@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    if save_user(username, password):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request, "error": "Пользователь уже существует"})

@app.get("/logout")
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        del sessions[session_id]
    response = RedirectResponse("/login")
    response.delete_cookie("session_id")
    return response
