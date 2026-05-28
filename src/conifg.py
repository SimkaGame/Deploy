import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key_123")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
STORAGE_DIR = "storage"
MAX_FILE_SIZE = 2 * 1024 * 1024
LOG_DIR = "logs"

cipher_suite = Fernet(ENCRYPTION_KEY.encode()) if ENCRYPTION_KEY else None