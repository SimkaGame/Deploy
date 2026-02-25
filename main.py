from dotenv import load_dotenv
import os
import sys
import hashlib

load_dotenv()

secret = os.getenv("APP_SECRET")

if not secret:
	print("Error")
	sys.exit(1)

h = hashlib.sha256(secret.encode()).hexdigest()[:3]
print(f"Secret hash: {h[:3]}**")
