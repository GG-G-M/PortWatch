# PortWatch config
import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    DATABASE = os.path.join(INSTANCE_DIR, "portwatch.db")
    NMAP_TIMEOUT = 300
    SCAN_PREFIXES = ["127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    LOG_LEVEL = "INFO"
