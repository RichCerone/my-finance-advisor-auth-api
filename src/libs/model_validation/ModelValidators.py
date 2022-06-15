from src.libs.api_models.Credentials import Credentials

def validate_credentials(credentials: Credentials):
    """
    Validates the credential data.

    Parameters
    ----------
    credentials: Credentials
        The credentials to be validated.

    Raises
    ------
    ValueError
        Raised if a parameter is invalid.
    """

    if credentials is None:
        raise ValueError("credentials must be defined.")

    if credentials.username is None or credentials.username.isspace():
        raise ValueError("username must be defined.")

    elif credentials.password is None or credentials.password.isspace():
        raise ValueError("password must be defined.")