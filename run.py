"""WSGI entry point: gunicorn run:app (production) or python run.py (local dev only)."""
from app import create_app

app = create_app(process_role="web")

if __name__ == "__main__":
    # Development server only; production uses gunicorn with TLS (see docker/entrypoint.sh).
    app.run(host="127.0.0.1", port=5000, debug=False)
