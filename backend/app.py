# app.py
import threading
from flask import Flask
from flask_cors import CORS
from routes.frontend_api import frontend_api
from routes.operator_api import operator_api
from routes.mitre_api import mitre_bp
from threading import Thread
from scheduler.updater import background_data_updater
from services.mitre_worker import start_worker
from routes.correlation_api import correlation_bp
from dotenv import load_dotenv
from scheduler.snort_normalize_worker import run as start_snort_normalizer
load_dotenv()
app = Flask(__name__)
CORS(
    app,
    resources={
        r"/api/*": {"origins": "*"},
        r"/rules": {"origins": "*"},
        r"/rules/*": {"origins": "*"},
    },
    supports_credentials=True,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"]
)
# Register Blueprints
app.register_blueprint(frontend_api)
app.register_blueprint(operator_api)
app.register_blueprint(mitre_bp)
app.register_blueprint(correlation_bp)
def start_background_services():
    t = threading.Thread(
        target=start_worker,
        daemon=True   # rất quan trọng
    )
    t.start()
    print("[APP] MITRE worker started in background")
    # Snort normalize worker
    t2 = threading.Thread(
        target=start_snort_normalizer,
        daemon=True
    )
    t2.start()
    print("[APP] Snort normalize worker started in background")


if __name__ == "__main__":
    start_background_services()
    Thread(target=background_data_updater, daemon=True).start()
    print("[Scheduler] Background updater started")
    app.run(host="0.0.0.0", port=5000)
