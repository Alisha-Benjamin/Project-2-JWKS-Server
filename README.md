# Project-2-JWKS-Server
Alisha Benjamin - anb0369 - alishabenjamin@my.unt.edu
CSCE 3550 - Foundations of Cyber Security
Project 1 - Basic JWKS Server
Language: Python

This project implements a JSON Web Key Set (JWKS) server using a SQLite database to store RSA private keys in PKCS1 PEM format. The server provides JWT signing functionality using these keys, and it allows the retrieval of public keys via a standard `.well-known/jwks.json` endpoint.

Run this program using :
python main.py

Test Client:
Ensure you run the test client on a separate IDE or Terminal instance:
curl -X POST http://localhost:8080/auth
curl -X POST http://localhost:8080/auth?expired=true

Test Suite: 
To obtain the coverage percentage for test_jwks_server.py, I used coverage.py. These are the steps to implement it to the test suite:
Pip install coverage
coverage run -m unittest discover
coverage report 



