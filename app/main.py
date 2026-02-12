import re
import unicodedata
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from .settings import CORS_ORIGINS
from .db import get_conn
from typing import Optional
from fastapi import Depends
from .auth import login_ok, issue_token, require_auth


app = FastAPI(title="URE Users API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Utilidades username ----------
STOPWORDS = {"de", "del", "la", "las", "los", "y"}

def normalize_text(s: str) -> str:
    s = s.strip().lower()
    s = "".join(
        c for c in unicodedata.normalize("NFD", s)
        if unicodedata.category(c) != "Mn"
    )
    s = s.replace("ñ", "n")
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def split_name(nombre: str):
    parts = [p for p in normalize_text(nombre).split(" ") if p and p not in STOPWORDS]
    # Esperado: nombres..., apellido_paterno, apellido_materno
    if len(parts) < 3:
        raise ValueError("Nombre debe incluir al menos: 2 nombres y 1 apellido (idealmente 2 apellidos).")
    return parts

def username_base_from_nombre(nombre: str) -> str:
    parts = split_name(nombre)
    # estrategia: últimos 2 tokens = apellidos
    apellido_materno = parts[-1]
    apellido_paterno = parts[-2]
    nombres = parts[:-2]
    n1 = nombres[0][0]
    n2 = nombres[1][0] if len(nombres) > 1 else ""
    base = f"{n1}{n2}{apellido_paterno}{apellido_materno[0]}"
    return base

def next_username(conn, base: str) -> str:
    # Trae el máximo sufijo usado para base y baseN
    sql = """
    SELECT
      COALESCE(
        MAX(
          NULLIF(regexp_replace(username, '^' || %(base)s || '(\\d+)?$', '\\1'), '')::int
        ),
        0
      ) AS max_suffix
    FROM public.situm_dep_usuarios
    WHERE username ~ ('^' || %(base)s || '(\\d+)?$');
    """
    row = conn.execute(sql, {"base": base}).fetchone()
    max_suffix = int(row["max_suffix"] or 0)

    # Si no hay sufijo pero base podría existir, esto ya lo contempla:
    # - Si base existe: max_suffix será 0 (porque base no captura \d). Entonces devolvemos base2.
    # Para detectar si base existe:
    exists = conn.execute(
        "SELECT 1 FROM public.situm_dep_usuarios WHERE username = %(u)s LIMIT 1;",
        {"u": base},
    ).fetchone()

    if not exists and max_suffix == 0:
        return base
    return f"{base}{max_suffix + 1 if max_suffix >= 1 else 2}"

# ---------- Modelos ----------
class UreOut(BaseModel):
    id: int
    cve_ure: str | None = None
    tag: str | None = None
    razon_social: str | None = None

class UserCreateIn(BaseModel):
    nombre: str = Field(min_length=3)
    email: str | None = None
    password: str = Field(min_length=1)
    unidad_responsable_id: int

class UserCreateOut(BaseModel):
    id: int
    username: str
    unidad_responsable_id: int

class LoginIn(BaseModel):
    username: str
    password: str

class LoginOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserOut(BaseModel):
    id: int
    nombre: str | None = None
    email: str | None = None
    username: str | None = None
    unidad_responsable_id: int | None = None
    cve_ure: str | None = None
    unidad_tag: str | None = None
    fecha_cambio: str | None = None
    ultima_actividad: str | None = None
    es_titular: bool | None = None
    estatus_general_id: int | None = None


# ---------- Endpoints ----------
@app.get("/unidades", response_model=list[UreOut])
def search_unidades(q: str = Query(default="", max_length=80)):
    q = q.strip()
    if len(q) < 2:
        return []

    sql = """
    SELECT id, cve_ure, tag, razon_social
    FROM public.situm_unidades_responsables
    WHERE habilitado IS TRUE
      AND (
        tag ILIKE '%%' || %(q)s || '%%'
        OR cve_ure ILIKE '%%' || %(q)s || '%%'
        OR razon_social ILIKE '%%' || %(q)s || '%%'
      )
    ORDER BY
      (cve_ure ILIKE %(q)s || '%%') DESC,
      (tag ILIKE %(q)s || '%%') DESC,
      tag ASC
    LIMIT 20;
    """
    with get_conn() as conn:
        rows = conn.execute(sql, {"q": q}).fetchall()
        return rows

@app.post("/usuarios", response_model=UserCreateOut)
def create_usuario(payload: UserCreateIn):
    try:
        base = username_base_from_nombre(payload.nombre)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    with get_conn() as conn:
        # Validar que la URE exista
        ure = conn.execute(
            "SELECT id FROM public.situm_unidades_responsables WHERE id = %(id)s LIMIT 1;",
            {"id": payload.unidad_responsable_id},
        ).fetchone()
        if not ure:
            raise HTTPException(status_code=400, detail="Unidad responsable no existe.")

        username = next_username(conn, base)

        sql_ins = """
        INSERT INTO public.situm_dep_usuarios
        (nombre, email, username, passwd, unidad_responsable_id, fecha_cambio)
        VALUES
        (%(nombre)s, %(email)s, %(username)s, md5(%(password)s), %(ure_id)s, CURRENT_DATE)
        RETURNING id, username, unidad_responsable_id;
        """
        row = conn.execute(sql_ins, {
            "nombre": payload.nombre,
            "email": payload.email,
            "username": username,
            "password": payload.password,
            "ure_id": payload.unidad_responsable_id,
        }).fetchone()
        conn.commit()

        return row

@app.get("/usuarios", response_model=list[UserOut])
def get_usuarios(
    q: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    _user: str = Depends(require_auth),
):
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100
    if offset < 0:
        offset = 0

    q = (q or "").strip()
    q_param = q if q else None

    sql = """
    SELECT
      u.id,
      u.nombre,
      u.email,
      u.username,
      u.unidad_responsable_id,
      ur.cve_ure,
      ur.tag AS unidad_tag,
      u.fecha_cambio,
      u.ultima_actividad,
      u.es_titular,
      u.estatus_general_id
    FROM public.situm_dep_usuarios u
    LEFT JOIN public.situm_unidades_responsables ur
      ON ur.id = u.unidad_responsable_id
    WHERE
      (%(q)s IS NULL)
      OR u.username ILIKE '%%' || %(q)s || '%%'
      OR u.nombre   ILIKE '%%' || %(q)s || '%%'
      OR u.email    ILIKE '%%' || %(q)s || '%%'
    ORDER BY u.id DESC
    LIMIT %(limit)s OFFSET %(offset)s;
    """
    with get_conn() as conn:
        rows = conn.execute(sql, {"q": q_param, "limit": limit, "offset": offset}).fetchall()
        return rows

