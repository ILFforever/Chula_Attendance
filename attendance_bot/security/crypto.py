"""
Secure password encryption/decryption module for attendance bot.

Uses cryptography.Fernet (AES-128-CBC with HMAC) for symmetric encryption.
The encryption key is stored as an environment variable (ENCRYPTION_KEY).

For fly.io deployment:
  flyctl secrets set ENCRYPTION_KEY=<your-32-byte-base64-key>

For local development:
  Set ENCRYPTION_KEY in your .env file or environment.
"""
import os
import base64
import logging
from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger("attendance-bot")


# -----------------------------------------------------------------------------
# Key Management
# -----------------------------------------------------------------------------
def generate_key() -> str:
    """Generate a new Fernet encryption key (32 bytes, base64-encoded)."""
    return Fernet.generate_key().decode('utf-8')


def get_encryption_key() -> bytes:
    """
    Get the encryption key from environment variable.

    Returns:
        bytes: The encryption key

    Raises:
        ValueError: If ENCRYPTION_KEY is not set or invalid
    """
    key_str = os.environ.get("ENCRYPTION_KEY", "")

    if not key_str:
        raise ValueError(
            "ENCRYPTION_KEY environment variable not set. "
            "Generate one with: python -c 'from password_crypto import generate_key; print(generate_key())' "
            "then set it in your environment or fly.io secrets."
        )

    try:
        # Ensure the key is valid base64
        key_bytes = key_str.encode('utf-8') if isinstance(key_str, str) else key_str
        # Validate it's a proper Fernet key (44 chars base64 = 32 bytes)
        if len(key_str) != 44:
            raise ValueError(
                f"Invalid ENCRYPTION_KEY length (expected 44 chars, got {len(key_str)}). "
                "Generate a new key with: python -c 'from password_crypto import generate_key; print(generate_key())'"
            )
        return key_bytes
    except Exception as e:
        raise ValueError(f"Invalid ENCRYPTION_KEY format: {e}")


def get_fernet() -> Fernet:
    """Get a Fernet cipher instance with the current key."""
    return Fernet(get_encryption_key())


# -----------------------------------------------------------------------------
# Password Encryption/Decryption
# -----------------------------------------------------------------------------
def encrypt_password(password: str) -> str:
    """
    Encrypt a password using Fernet symmetric encryption.

    Args:
        password: The plaintext password to encrypt

    Returns:
        str: Base64-encoded encrypted password (token)

    Raises:
        ValueError: If ENCRYPTION_KEY is not properly configured
    """
    if not password:
        return ""

    try:
        fernet = get_fernet()
        # Fernet expects bytes, returns bytes
        encrypted = fernet.encrypt(password.encode('utf-8'))
        return encrypted.decode('utf-8')
    except Exception as e:
        log.error("Failed to encrypt password: %s", e)
        raise ValueError(f"Password encryption failed: {e}") from e


def decrypt_password(encrypted_password: str) -> str:
    """
    Decrypt a password that was encrypted with encrypt_password().

    Args:
        encrypted_password: The base64-encoded encrypted password

    Returns:
        str: The plaintext password

    Raises:
        ValueError: If decryption fails (wrong key or corrupted data)
    """
    if not encrypted_password:
        return ""

    try:
        fernet = get_fernet()
        decrypted = fernet.decrypt(encrypted_password.encode('utf-8'))
        return decrypted.decode('utf-8')
    except InvalidToken:
        raise ValueError(
            "Failed to decrypt password - the ENCRYPTION_KEY may have changed. "
            "Users will need to re-register their credentials."
        )
    except Exception as e:
        log.error("Failed to decrypt password: %s", e)
        raise ValueError(f"Password decryption failed: {e}") from e


# -----------------------------------------------------------------------------
# Password Field Detection
# -----------------------------------------------------------------------------
def is_encrypted(value: str) -> bool:
    """
    Check if a password value appears to be encrypted (Fernet token).

    Fernet tokens are base64 and always start with specific characters
    and have a specific length structure. This is a heuristic check.

    Args:
        value: The password value to check

    Returns:
        bool: True if the value looks like a Fernet token
    """
    if not value or len(value) < 44:
        return False
    try:
        # Fernet tokens are valid base64
        decoded = base64.urlsafe_b64decode(value + '==')  # Add padding if needed
        # Real Fernet tokens decode to specific format:
        # version (1 byte) + timestamp (8 bytes) + IV (16 bytes) + ...
        return len(decoded) >= 25
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Migration Helper
# -----------------------------------------------------------------------------
def migrate_plaintext_to_encrypted(users_dict: dict) -> tuple[dict, int]:
    """
    Migrate a users dictionary from plaintext passwords to encrypted.

    Args:
        users_dict: The users dictionary with plaintext passwords

    Returns:
        tuple: (migrated_dict, count_of_migrated_users)

    Raises:
        ValueError: If ENCRYPTION_KEY is not set
    """
    migrated = {}
    count = 0

    for uid, user_data in users_dict.items():
        password = user_data.get("password", "")

        # Skip if already encrypted
        if is_encrypted(password):
            migrated[uid] = user_data
            continue

        # Encrypt the password
        try:
            encrypted = encrypt_password(password)
            migrated[uid] = {
                **user_data,
                "password": encrypted,
                "encrypted": True  # Marker to track migration
            }
            count += 1
            log.info("Migrated password for user %s", user_data.get("username", uid))
        except Exception as e:
            log.error("Failed to migrate password for user %s: %s", uid, e)
            # Keep original on failure
            migrated[uid] = user_data

    return migrated, count


if __name__ == "__main__":
    # CLI utilities for key generation and testing
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "generate-key":
        print("Generating new encryption key:")
        print(generate_key())
        print("\nAdd this to your environment:")
        print(f"export ENCRYPTION_KEY='{generate_key()}'")
        print("\nOr for fly.io:")
        print(f"flyctl secrets set ENCRYPTION_KEY='{generate_key()}'")
    elif len(sys.argv) > 1 and sys.argv[1] == "test":
        # Test encryption/decryption
        os.environ['ENCRYPTION_KEY'] = generate_key()
        test_pwd = "TestPassword123!"
        enc = encrypt_password(test_pwd)
        dec = decrypt_password(enc)
        print(f"Original:  {test_pwd}")
        print(f"Encrypted: {enc}")
        print(f"Decrypted: {dec}")
        print(f"Match: {test_pwd == dec}")
    else:
        print("Usage:")
        print("  python password_crypto.py generate-key  # Generate a new key")
        print("  python password_crypto.py test          # Test encryption")
