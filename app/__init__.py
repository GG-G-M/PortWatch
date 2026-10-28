import os
from flask import Flask
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    os.makedirs(app.config["INSTANCE_DIR"], exist_ok=True)
    return app
