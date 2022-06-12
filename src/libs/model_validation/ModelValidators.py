from src.libs.api_models.Credentials import Credentials

def validateCredentials(credentials: Credentials):
    if credentials is None:
        raise ValueError("credential must be defined.")

    if credentials.username is None or credentials.username.isspace():
        raise ValueError("username must be defined.")

    elif credentials.password is None or credentials.password.isspace():
        raise ValueError("password must be defined.")