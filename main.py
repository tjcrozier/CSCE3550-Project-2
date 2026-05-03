from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "localhost"
serverPort = 8080

databaseConnection = sqlite3.connect("totally_not_my_privateKeys.db")
cursor = databaseConnection.cursor()


# serialize key to blob 
cursor.execute('''
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
''')


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

# insert sample data (1 key expiring now, 1 expiring in an hour)
cursor.execute('''
    INSERT INTO keys
        (kid, key, exp) VALUES (?, ?, ?)''', (0, pem,datetime.datetime.now(datetime.timezone.utc).timestamp() + 3600))

cursor.execute('''
    INSERT INTO keys
        (kid, key, exp) VALUES (?, ?, ?)''', (1, expired_pem,datetime.datetime.now(datetime.timezone.utc).timestamp() - 3600))

# for i in cursor.execute("SELECT kid, key FROM keys"):
#     print(i)
# end demo nonsense

# numbers = private_key.private_numbers()


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
    # all of these request types just bork
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


    #   
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)


            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return
    
    # Reads all valid (non-expired) private keys from the DB. 
    # Creates a JWKS response from those private keys.
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            currentTime = datetime.datetime.now(datetime.timezone.utc).timestamp()
            
                    
            # query for expiry times later than current time
            keys = {
                "keys": []
            }

            for i in cursor.execute('SELECT kid, key, exp FROM keys'):
                if i[2] > currentTime:
                    currentKeyNumbers = serialization.load_pem_private_key(i[1], password=None).private_numbers()
                    keys["keys"].append({
                        # might need to change these fields later :P
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": i[0],
                        "n": int_to_base64(currentKeyNumbers.public_numbers.n),
                        "e": int_to_base64(currentKeyNumbers.public_numbers.e),
                    })
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server up")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Shutting down...")

    webServer.server_close()
