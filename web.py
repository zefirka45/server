import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# Предполагаем, что класс Base написан корректно и поддерживает контекстный менеджер
from base import Base

app = FastAPI()
templates = Jinja2Templates(directory="templates")

SECRET_KEY = "mndgkfjkdnjfg43345sfd"  # В реальном проекте вынесите в .env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# Форма для входа (GET)
@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    # Явно передаем request=request для совместимости с новыми версиями FastAPI
    return templates.TemplateResponse(request=request, name="login.html")


@app.post("/login")
async def login_process(
    request: Request, 
    login: str = Form(default=""), 
    password: str = Form(default="")
):
    # Очищаем строки от случайных пробелов по краям
    login = login.strip()
    password = password.strip()

    # Проверяем на заполненность полей
    if not login or not password:
        return templates.TemplateResponse(
            request=request, 
            name="login.html", 
            context={"error": "Заполните все поля"}
        )

    with Base() as db:
        db.create_table()
        user = db.select_table(login)
        
        if user is None:
            return templates.TemplateResponse(
                request=request, 
                name="login.html", 
                context={"error": "Неверный логин или пароль"}
            )
        
        is_active = user['ACTIVE']       
        if is_active == 1:
            base_password = user['PASS']
                
                
                # Если в БД пароль лежит как строка (str), кодируем его в bytes
            if isinstance(base_password, str):
                base_password = base_password.encode("utf-8")
                    
                form_password = password.encode("utf-8")
                
                # Проверяем пароль
                if bcrypt.checkpw(form_password, base_password):
                    time_now = datetime.now(timezone.utc)
                    expire = time_now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
                    
                    payload = {
                        "sub": login,
                        "iat": time_now,
                        "exp": expire
                    }
                    
                    encode_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
                    
                    # Вариант А: Если делаем API — отдаем токен в JSON
                    return {"access_token": encode_jwt, "token_type": "bearer"}
                
                else: 
                    return templates.TemplateResponse(
                        request=request, 
                        name="login.html", 
                        context={"error": "Неверный логин или пароль"}
            )
        else:
            return templates.TemplateResponse(
                request=request,
                name = "login.html",
                context={"error":"Учетная запись отключена"}
            )

