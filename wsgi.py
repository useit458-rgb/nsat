"""
WSGI entrypoint script for Network Security Assessment Toolkit (NSAT).
"""
import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app

app = create_app(os.getenv("FLASK_ENV", "default"))

if __name__ == "__main__":
    is_cloud = bool(os.getenv("PORT") or os.getenv("RAILWAY_ENVIRONMENT"))
    default_host = "0.0.0.0" if is_cloud else "127.0.0.1"
    host = os.getenv("SERVER_HOST", app.config.get("SERVER_HOST", default_host))
    port = int(os.getenv("PORT", app.config.get("SERVER_PORT", 5000)))
    print(f"[*] Starting NSAT on http://{host}:{port}")
    app.run(host=host, port=port, debug=app.config.get("DEBUG", False))
