import psycopg
from psycopg.rows import dict_row
from .settings import DATABASE_URL

def get_conn():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)
