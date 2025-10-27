import time
import requests
import subprocess
import signal
import signal
import os
import platform

def start_server():
    #Start JWKS server and wait until port 8080 is open
    process = subprocess.Popen(
        ["python", "main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for the server to start listening
    import socket

    #try for 10s
    for _ in range(20): 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(("localhost", 8080))
        sock.close()
        if result == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("Server did not start in time")

    return process

def stop_server(process):
    if platform.system() == "Windows":
        process.terminate()
    else:
        process.send_signal(signal.SIGINT)
    process.wait(timeout = 5)

#test get endpoint .well-known/jwks.json
def test_jwks():

    server = start_server()

    try:
        response = requests.get("http://localhost:8080/.well-known/jwks.json")
        assert response.status_code == 200
        
        data = response.json()

        assert "keys" in data
        assert len(data["keys"]) > 0

        key = data["keys"][0]
        assert key["alg"] == "RS256"
        assert key["kty"] == "RSA"
        assert "n" in key and "e" in key

    finally:
        stop_server(server)

#test post endpoint /auth
def test_auth():

    server = start_server()

    try:
        res = requests.post("http://localhost:8080/auth")
        assert res.status_code == 200
        token = res.text.strip()
        assert token.startswith("eyJ")

        res2 = requests.post("http://localhost:8080/auth?expired=true")
        assert res2.status_code == 200
        expired_token = res2.text.strip()
        assert expired_token.startswith("eyJ")
        

    finally:
        stop_server(server)