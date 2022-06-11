from fastapi.testclient import TestClient
from src.main import app, Token
from src.libs.api_models.Credentials import Credentials

# Setup
client = TestClient(app)

# Test
def test_create_token_creates_token():
    creds = Credentials(username="user",password="pass")
    response = client.post("/token/", data=creds.json())

    assert response.status_code == 200
    
    token = response.json()
    r = Token(**token)
    assert type(r) == Token
    