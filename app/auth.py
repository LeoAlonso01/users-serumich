import time
import jwt
from fastapi import HTTPException, Header
from .settings import ADMIN_USER, ADMIN_PASS, JWT_SECRET

JWT_ALG = "HS256"
JWT_TTL_SECONDS = 60 * 60 * 8  # 8 horas

def login_ok(user: str, password: str) -> bool:
    return user == ADMIN_USER and password == ADMIN_PASS

def issue_token(user: str) -> str:
    now = int(time.time())
    payload = {"sub": user, "iat": now, "exp": now + JWT_TTL_SECONDS}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def require_auth(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Falta token Bearer.")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return str(payload.get("sub", ""))
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado.")
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido.")
