#!/usr/bin/env python3
"""
Generate a development API key for the Terraform Registry backend
"""
import secrets
import base64
import bcrypt

# Generate a 32-byte random key
random_bytes = secrets.token_bytes(32)
random_part = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')

# Create full key with prefix
prefix = "dev"
full_key = f"{prefix}_{random_part}"

# Hash the key with bcrypt
key_hash = bcrypt.hashpw(full_key.encode('utf-8'), bcrypt.gensalt(rounds=10)).decode('utf-8')

# Display prefix (first 10 chars)
display_prefix = full_key[:10]

print("="*60)
print("Development API Key Generated")
print("="*60)
print(f"\nFull API Key (use this in your requests):")
print(f"  {full_key}")
print(f"\nBcrypt Hash (for database):")
print(f"  {key_hash}")
print(f"\nDisplay Prefix (for database):")
print(f"  {display_prefix}")
print("\n" + "="*60)
print("SQL to insert into database:")
print("="*60)
print(f"""
UPDATE api_keys 
SET key_hash = '{key_hash}',
    key_prefix = '{display_prefix}'
WHERE user_id = (SELECT id FROM users WHERE email = 'admin@dev.local');
""")
print("\n" + "="*60)
print("Usage in API requests:")
print("="*60)
print(f"Authorization: Bearer {full_key}")
print("="*60)
