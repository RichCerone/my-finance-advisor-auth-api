from fastapi.testclient import TestClient
from src.main import app, inject_jwt_bearer, Settings, Credentials, User, json, init_settings, init_users_db, init_token_helper, init_bcrypt_helper, authorize_access
from unittest.mock import Mock

# Setup
def init_settings_override():
    return Settings(
        secret_key="some_key", 
        algorithm="some_algo", 
        access_token_expire_minutes=30,
        endpoint="some_endpoint", 
        key="some_key",
        database_id="some_id",
        container_id="some_id"
    )

def init_jwt_bearer_override_success():
    return "some_token"
    
def init_users_db_override_get_success():
    users_db_mock = Mock()
    users_db_mock.get.return_value = json.dumps(User("user", "password").__dict__)

    return users_db_mock

def init_users_db_override_upsert_201():
    users_db_mock = Mock()
    users_db_mock.get.return_value = None
    users_db_mock.upsert.return_value = json.dumps({"user": "some_username", "password": "some_password"})

    return users_db_mock

def init_users_db_override_upsert_500():
    users_db_mock = Mock()
    users_db_mock.get.return_value = None
    users_db_mock.upsert.side_effect = Exception()

    return users_db_mock

def init_bcrypt_helper_override_success():
    bcrypt_helper_mock = Mock()
    bcrypt_helper_mock.get_password_hash.return_value = "some_hash"

    return bcrypt_helper_mock

def init_token_helper_override_success():
    token_helper_mock = Mock()
    token_helper_mock.create_access_token.return_value = "dummy_token"

    return token_helper_mock

def init_authorize_access_success():
    return "some_user"

client = TestClient(app)
app.dependency_overrides[init_settings] = init_settings_override # Override for all tests.

# Test
# Assert a 201 status code is returned.
def test_create_user_returns_201():
    app.dependency_overrides[inject_jwt_bearer] = init_jwt_bearer_override_success
    app.dependency_overrides[authorize_access] = init_authorize_access_success
    app.dependency_overrides[init_users_db] = init_users_db_override_upsert_201
    app.dependency_overrides[init_bcrypt_helper] = init_bcrypt_helper_override_success
    app.dependency_overrides[init_token_helper] = init_token_helper_override_success

    creds = Credentials(username="user",password="password")
    response = client.post("/users/", data=creds.json())

    assert response.status_code == 201

# Assert a 400 status code is returned.
def test_create_user_returns_400():
    creds = Credentials(username=" ",password="password")
    response = client.post("/users/", data=creds.json())

    assert response.status_code == 400

# Assert a 409 status code 
def test_create_user_returns_409():
    app.dependency_overrides[inject_jwt_bearer] = init_jwt_bearer_override_success
    app.dependency_overrides[authorize_access] = init_authorize_access_success
    app.dependency_overrides[init_users_db] = init_users_db_override_get_success
    app.dependency_overrides[init_bcrypt_helper] = init_bcrypt_helper_override_success
    app.dependency_overrides[init_token_helper] = init_token_helper_override_success

    creds = Credentials(username="user",password="password")
    response = client.post("/users/", data=creds.json())

    assert response.status_code == 409

# Assert a 500 status code is returned.
def test_create_user_returns_500():
    app.dependency_overrides[inject_jwt_bearer] = init_jwt_bearer_override_success
    app.dependency_overrides[authorize_access] = init_authorize_access_success
    app.dependency_overrides[init_users_db] = init_users_db_override_upsert_500
    app.dependency_overrides[init_bcrypt_helper] = init_bcrypt_helper_override_success
    app.dependency_overrides[init_token_helper] = init_token_helper_override_success

    creds = Credentials(username="user",password="password")
    response = client.post("/users/", data=creds.json())

    assert response.status_code == 500