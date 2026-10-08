import os

from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    from setproctitle import setproctitle
    setproctitle("Oxsium:Web Engine")
except ImportError:
    pass

app = Flask(__name__)

CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"],
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["10000 per day", "1000 per hour"],
    storage_uri=os.getenv("REDIS_URL", "memory://"),
)