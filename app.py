"""Smart Cloud Shield: Server Launcher.

Usage:
    python app.py
"""
import os
from scs import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"Starting Smart Cloud Shield on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug)
