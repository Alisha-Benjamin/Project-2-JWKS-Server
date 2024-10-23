# Project-2-JWKS-Server<br/>
Alisha Benjamin - anb0369 - alishabenjamin@my.unt.edu<br/>
CSCE 3550 - Foundations of Cyber Security<br/>
Project 2 - Basic JWKS Server<br/>
Language: Python<br/>

This project implements a JSON Web Key Set (JWKS) server using a SQLite database to store RSA private keys in PKCS1 PEM format. The server provides JWT signing functionality using these keys, and it allows the retrieval of public keys via a standard `.well-known/jwks.json` endpoint.<br/>

Run this program using :<br/>
python main.py<br/><br/>

Test Client:
Ensure you run the test client on a separate IDE or Terminal instance:<br/>
curl -X POST http://localhost:8080/auth <br/>
curl -X POST http://localhost:8080/auth?expired=true<br/><br/>

Test Suite: <br/>
To obtain the coverage percentage for test_jwks_server.py, I used coverage.py. These are the steps to implement it to the test suite:<br/>
Pip install coverage<br/>
coverage run -m unittest discover<br/>
coverage report <br/>



