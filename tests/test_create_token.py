import json

from fastapi.testclient import TestClient
from jose import JWTError
from src.data_models.User import User
from src.main import app, Token, init_users_db, init_token_helper, init_bcrypt_helper
from src.libs.api_models.Credentials import Credentials
from unittest.mock import Mock

# Setup
def init_users_db_override_201():
    users_db_mock = Mock()
    users_db_mock.get.return_value = json.dumps(User("user", "password").__dict__)

    return users_db_mock


def init_users_db_override_404():
    users_db_mock = Mock()
    users_db_mock.get.return_value = None

    return users_db_mock


def init_users_db_override_500():
    users_db_mock = Mock()
    users_db_mock.get.side_effect = Exception()

    return users_db_mock


def init_token_helper_override_success():
    token_helper_mock = Mock()
    token_helper_mock.create_access_token.return_value = "dummy_token"

    return token_helper_mock


def init_token_helper_override_error():
    token_helper_mock = Mock()
    token_helper_mock.create_access_token.side_effect = JWTError()

    return token_helper_mock


def init_bcrypt_helper_override_success():
    bcrypt_helper_mock = Mock()
    bcrypt_helper_mock.verify_password.return_value = True

    return bcrypt_helper_mock


def init_bcrypt_helper_override_failure():
    bcrypt_helper_mock = Mock()
    bcrypt_helper_mock.verify_password.return_value = False

    return bcrypt_helper_mock

client = TestClient(app)

# Test
# Assert a 201 status code is returned.
def test_create_token_returns_201():
    app.dependency_overrides[init_users_db] = init_users_db_override_201
    app.dependency_overrides[init_bcrypt_helper] = init_bcrypt_helper_override_success
    app.dependency_overrides[init_token_helper] = init_token_helper_override_success

    creds = Credentials(username="user",password="password")
    response = client.post("/token/", data=creds.json())

    assert response.status_code == 201
    
    token = response.json()
    r = Token(**token)
    assert type(r) == Token


# Assert a 400 status code is returned.
def test_create_token_returns_400():
    creds = Credentials(username=" ",password="password")
    response = client.post("/token/", data=creds.json())

    assert response.status_code == 400


# Asserts a 401 status code is returned.
def test_create_token_returns_401():
    app.dependency_overrides[init_users_db] = init_users_db_override_201
    app.dependency_overrides[init_bcrypt_helper] = init_bcrypt_helper_override_failure
    app.dependency_overrides[init_token_helper] = init_token_helper_override_success

    creds = Credentials(username="user_a",password="password")
    response = client.post("/token/", data=creds.json())

    assert response.status_code == 401


# Assert a 404 status code is returned.
def test_create_token_returns_404():
    app.dependency_overrides[init_users_db] = init_users_db_override_404

    creds = Credentials(username="user_a",password="password")
    response = client.post("/token/", data=creds.json())

    assert response.status_code == 404

# Assert a 500 status code is returned.
def test_create_token_returns_500():
    # Token creation error.
    app.dependency_overrides[init_users_db] = init_users_db_override_201
    app.dependency_overrides[init_bcrypt_helper] = init_bcrypt_helper_override_success
    app.dependency_overrides[init_token_helper] = init_token_helper_override_error

    creds = Credentials(username="user_a",password="password")
    response = client.post("/token/", data=creds.json())

    assert response.status_code == 500

    # Unexpected error.
    app.dependency_overrides[init_users_db] = init_users_db_override_500
    app.dependency_overrides[init_bcrypt_helper] = init_bcrypt_helper_override_success
    app.dependency_overrides[init_token_helper] = init_token_helper_override_success

    creds = Credentials(username="user_a",password="password")
    response = client.post("/token/", data=creds.json())

    assert response.status_code == 500