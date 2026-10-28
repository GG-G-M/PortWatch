import os
import sys

# Ensure repo root is on path
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(ROOT))

from app import create_app

app = create_app()

@app.route("/")
def index():
    return "PortWatch"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5091, debug=True)
