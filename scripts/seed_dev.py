import hashlib
import os
import secrets
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from src.auth import hash_password
from src.storage import event_store

DEV_CLIENT_NAME = 'local-dev'
DEV_KEY_OVERRIDE = os.getenv('DEV_API_KEY')
DEV_ADMIN_USERNAME = os.getenv('DEV_ADMIN_USERNAME', 'admin')
DEV_ADMIN_PASSWORD = os.getenv('DEV_ADMIN_PASSWORD', 'change-me-in-production')


def seed():
    # ── API key ───────────────────────────────────────────────────────────────
    existing = event_store.get_api_key_by_client(DEV_CLIENT_NAME)
    if existing:
        print(f'Dev key already exists for {DEV_CLIENT_NAME}')
    else:
        raw_key = DEV_KEY_OVERRIDE or secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        event_store.create_api_key(key_hash, DEV_CLIENT_NAME, rate_limit=1000)
        print("Dev API key created:")
        print(f"  Client:  {DEV_CLIENT_NAME}")
        print(f"  Key:     {raw_key}")

    # ── Admin user ────────────────────────────────────────────────────────────
    if event_store.user_exists(DEV_ADMIN_USERNAME):
        print(f'Admin user already exists: {DEV_ADMIN_USERNAME}')
    else:
        password_hash = hash_password(DEV_ADMIN_PASSWORD)
        event_store.create_user_account(
            username=DEV_ADMIN_USERNAME,
            email=None,
            password_hash=password_hash,
            is_admin=True,
        )
        print("Admin user created:")
        print(f"  Username: {DEV_ADMIN_USERNAME}")
        if DEV_ADMIN_PASSWORD == 'change-me-in-production':
            print("  Password: change-me-in-production  ← CHANGE THIS!")
        else:
            print("  Password: (from DEV_ADMIN_PASSWORD env var)")


if __name__ == '__main__':
    seed()
