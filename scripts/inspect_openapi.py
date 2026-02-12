import traceback
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import app

try:
    app.openapi()
    print('OPENAPI_GENERATED')
except Exception as e:
    traceback.print_exc()