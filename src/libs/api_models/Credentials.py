from pydantic import BaseModel

class Credentials(BaseModel):
    """
    Credentials for accessing the API.
    """

    username: str
    password: str