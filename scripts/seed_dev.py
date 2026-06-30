import hashlib
import os
import secrets
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from src.storage import event_store

DEV_CLIENT_NAME = 'local-dev'
DEV_KEY_OVERRIDE = os.getenv('DEV_API_KEY')


def seed():
    existing = event_store.get_api_key_by_client(DEV_CLIENT_NAME)
    if existing:
        print(f'Dev key already exists for {DEV_CLIENT_NAME}')
        return
    raw_key = DEV_KEY_OVERRIDE or secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    event_store.create_api_key(key_hash, DEV_CLIENT_NAME, rate_limit=1000)

    print("Dev API key created:")
    print(f"  Clilent: {DEV_CLIENT_NAME}")
    print(f"  Key:     {raw_key}")


if __name__ == '__main__':
  seed()
