import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]

ADMIN_USER = os.getenv("ADMIN_USER", "")
ADMIN_PASS = os.getenv("ADMIN_PASS", "")
JWT_SECRET = os.getenv("JWT_SECRET", "")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL no está configurada en .env")
if not ADMIN_USER or not ADMIN_PASS or not JWT_SECRET:
    raise RuntimeError("Faltan ADMIN_USER / ADMIN_PASS / JWT_SECRET en .env")
