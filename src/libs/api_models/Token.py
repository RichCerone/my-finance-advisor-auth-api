from pydantic import BaseModel

class Token(BaseModel):
    """
    The token for API authorization use.
    """

    token: str
    token_type: str