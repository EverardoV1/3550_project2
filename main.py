from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import time


hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()
db_file = "totally_not_my_privatekeys.db"


def init_db():
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS keys(
              kid INTEGER PRIMARY KEY AUTOINCREMENT,
              key BLOB NOT NULL,
              exp INTEGER NOT NULL
            )

    """)
    conn.commit()
    return conn


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            expired = "expired" in params
            row = get_key(conn, expired)
            if not row:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No key found in database")
                return

            # Determine which key to use
            if expired:
                active_key = expired_key
                kid = "expiredKID"
            else:
                active_key = private_key
                kid = "goodKID"

            # Get exp time from db
            _, exp_ts = row

            payload = {
                "user": "userABC",
                "exp": datetime.datetime.utcfromtimestamp(exp_ts)
            }
            headers = {"kid": kid}

            # Sign using correct key
            encoded_jwt = jwt.encode(payload, active_key, algorithm="RS256", headers=headers)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(encoded_jwt.encode("utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            # Extract public key numbers for both keys
            good_numbers = private_key.private_numbers().public_numbers
            expired_numbers = expired_key.private_numbers().public_numbers

            jwks = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(good_numbers.n),
                        "e": int_to_base64(good_numbers.e),
                    },
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "expiredKID",
                        "n": int_to_base64(expired_numbers.n),
                        "e": int_to_base64(expired_numbers.e),
                    },
                ]
            }

            # Send JWKS JSON response
            self.wfile.write(json.dumps(jwks).encode("utf-8"))
            return

        
        #self.send_response(405)
        self.end_headers()

def get_key(conn, expired=False):
    c = conn.cursor()
    now = int(time.time())
    if expired:
        c.execute("SELECT key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (now,))
    else:
        c.execute("SELECT key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (now,))
    return c.fetchone()

def get_valid_keys(conn):
    c = conn.cursor()
    now = int(time.time())
    c.execute("SELECT key FROM keys WHERE exp > ?", (now,))
    return [row[0] for row in c.fetchall()]


if __name__ == "__main__":

    conn = init_db()

    def save_key_to_db(conn, key_pem, exp_timestamp):
        c = conn.cursor()
        c.execute("INSERT INTO keys (key,exp) VALUES (?, ?)", (key_pem, exp_timestamp))
        conn.commit()

    def seed_keys(conn):
        now = int(time.time())
        hour_later = now + 3600

        save_key_to_db(conn, pem, hour_later)
        save_key_to_db(conn, expired_pem, now - 10)

    seed_keys(conn)    

    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"server started at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    