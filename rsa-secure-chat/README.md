# RSA-Based Secure Message Communication System

Flask + SQLite web app. Messages use **hybrid encryption**: a random AES-256-GCM key encrypts the
message, and that key is wrapped with the receiver's RSA-2048 public key (OAEP, SHA-256).

## Run
```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py            # open http://127.0.0.1:5000
python -m unittest discover -v   # security tests
```

## Demo script
1. Register `alice` and `bob` (use two browsers/profiles). Save each private key.
2. Log in as alice, send a message to bob. Note the ciphertext shown.
3. Log in as bob, paste bob's private key, click Decrypt -> plaintext appears.
4. Paste alice's key instead -> "Decryption failed" (wrong-key test).

## API
| Method | Endpoint | Purpose |
|---|---|---|
| POST | /api/register, /api/login, /api/logout | accounts + RSA key generation |
| GET | /api/users, /api/users/<name>/public_key | directory |
| POST | /api/send | encrypt with receiver public key, store ciphertext |
| GET | /api/inbox, /api/sent | ciphertext + metadata |
| POST | /api/decrypt | decrypt with supplied private key (receiver only) |

## Known limitations (mention in your report)
- Encryption/decryption run on the server for simplicity, so the server briefly sees plaintext on send
  and the private key on decrypt. True end-to-end security would do both in the browser (Web Crypto API).
- Private key is not password-protected; no signatures, so sender authenticity is not proven.
- Use HTTPS in any real deployment; there is no rate limiting or CSRF token (SameSite cookies only).
