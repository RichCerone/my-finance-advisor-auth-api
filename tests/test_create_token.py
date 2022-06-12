from fastapi.testclient import TestClient
from src.main import app, Token
from src.libs.api_models.Credentials import Credentials

# Setup
client = TestClient(app)

# Test
# Assert a 201 status code is returned.
def test_create_token_returns_201():
    creds = Credentials(username="rich",password="myhashedpassword")
    response = client.post("/token/", data=creds.json())

    assert response.status_code == 201
    
    token = response.json()
    r = Token(**token)
    assert type(r) == Token


# Assert a 400 status code is returned.
def test_create_token_returns_400():
    creds = Credentials(username=" ",password="myhashedpassword")
    response = client.post("/token/", data=creds.json())

    assert response.status_code == 400


# Assert a 404 status code is returned.
def test_create_token_returns_404():
    creds = Credentials(username="user_a",password="myhashedpassword")
    response = client.post("/token/", data=creds.json())

    assert response.status_code == 404