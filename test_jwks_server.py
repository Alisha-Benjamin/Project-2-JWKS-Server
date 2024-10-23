import unittest
import requests
import sqlite3
import time
import json
import datetime

# Host and port for the JWKS server
host = "http://localhost:8080"

# Test the JWKS server
class TestJWKS(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """ Ensure the JWKS server is running before starting tests. """
        # Check if the server is reachable
        try:
            requests.get(f"{host}/.well-known/jwks.json", timeout=5)
        except requests.ConnectionError:
            raise Exception("JWKS server is not running. Please start the server before running tests.")

    def test_db_insertion(self):
        """ Test if keys are being inserted into the database correctly. """
        conn = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM keys")
        rows = cursor.fetchall()

        self.assertGreaterEqual(len(rows), 2, "At least two keys (valid and expired) should be inserted.")

    def test_auth_valid_jwt(self):
        """ Test if /auth returns a valid JWT. """
        response = requests.post(f"{host}/auth")
        self.assertEqual(response.status_code, 200)

        jwt_token = response.text
        self.assertTrue(jwt_token, "JWT token should be returned for valid auth.")

    def test_auth_expired_jwt(self):
        """ Test if /auth?expired=true returns an expired JWT. """
        response = requests.post(f"{host}/auth?expired=true")
        self.assertEqual(response.status_code, 200)

        jwt_token = response.text
        self.assertTrue(jwt_token, "JWT token should be returned for expired auth.")

    def test_well_known_jwks(self):
        """ Test if /well-known/jwks.json returns valid public keys. """
        response = requests.get(f"{host}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)

        jwks = response.json()
        self.assertIn("keys", jwks, "JWKS should contain 'keys' field.")
        self.assertGreaterEqual(len(jwks["keys"]), 1, "At least one valid key should be returned.")

    def test_invalid_endpoint(self):
        """ Test that accessing an invalid endpoint returns 405 status code. """
        response = requests.get(f"{host}/invalid-endpoint")
        self.assertEqual(response.status_code, 405)


if __name__ == "__main__":
    unittest.main()
