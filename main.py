from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# @app.get("/", response_class=HTMLResponse)
# def get_start_page(request: Request):
#     return templates.TemplateResponse("main.html", {"request": request})

@app.get("/main", response_class=HTMLResponse)
def get_start_page(request: Request):
    return templates.TemplateResponse("main.html", {"request": request})
