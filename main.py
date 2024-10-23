from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

hostName = "localhost"
serverPort = 8080

# Database setup with error handling
db_file = "totally_not_my_privateKeys.db"

# Check if the database file exists and is a valid SQLite file
if os.path.exists(db_file):
    try:
        # Try connecting to the existing database
        conn = sqlite3.connect(db_file)
        conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
    except sqlite3.DatabaseError:
        print(f"{db_file} is not a valid SQLite database. Deleting and recreating...")
        conn.close()
        os.remove(db_file)
        conn = sqlite3.connect(db_file)
else:
    # Create a new database if it doesn't exist
    conn = sqlite3.connect(db_file)

def create_table():
    with conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS keys(
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL
                    )''')

# Call the function to create the table if it doesn't exist
create_table()

# Your existing key generation logic
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

# Function to save the keys to the database
def save_key_to_db(kid, key_pem, exp):
    with conn:
        conn.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (kid, key_pem, exp))
        #print(f"Saved key with kid={kid}, exp={exp} to the database.")

# Save the keys on program start
save_key_to_db(1, pem.decode(), int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()))  # Valid key
# Set the expired key to 7 days in the past
save_key_to_db(2, expired_pem.decode(), int((datetime.datetime.utcnow() - datetime.timedelta(days=7)).timestamp()))


# Function to check the contents of the database (for debugging purposes)
def check_db_contents():
    with conn:
        result = conn.execute("SELECT kid, exp FROM keys")
        rows = result.fetchall()
        #print("Database contents:")
        #for row in rows:
            #exp_time = datetime.datetime.utcfromtimestamp(row[1]).strftime('%Y-%m-%d %H:%M:%S')
            #print(f"KID: {row[0]}, Exp: {exp_time}")

# Debugging: Check the database contents after saving keys
check_db_contents()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Function to get a key from the database (expired or valid)
def get_key_from_db(expired=False):
    with conn:
        if expired:
            print("Fetching expired key from DB")
            result = conn.execute("SELECT key, exp FROM keys WHERE exp < ?", (int(datetime.datetime.utcnow().timestamp()),))
        else:
            print("Fetching valid key from DB")
            result = conn.execute("SELECT key, exp FROM keys WHERE exp >= ?", (int(datetime.datetime.utcnow().timestamp()),))
        
        key_row = result.fetchone()
        #print(f"Fetched key: {key_row}") 
        return key_row

# HTTP Server logic remains unchanged
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
            expired = 'expired' in params
            key_row = get_key_from_db(expired)

            if key_row:
                selected_key_pem = key_row[0]
                headers = {"kid": "expiredKID" if expired else "goodKID"}

                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.utcnow() + (datetime.timedelta(hours=-1) if expired else datetime.timedelta(hours=1))
                }

                encoded_jwt = jwt.encode(token_payload, selected_key_pem.encode(), algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.send_response(404)  # No key found
                self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            valid_keys = get_key_from_db(False)  # Get valid keys only
            keys = {"keys": []}

            if valid_keys:
                key_pem = valid_keys[0]
                key = serialization.load_pem_private_key(key_pem.encode(), password=None)

                numbers = key.private_numbers()
                jwk = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                }
                keys["keys"].append(jwk)

            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
        else:
            self.send_response(405)
            self.end_headers()
        return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()

