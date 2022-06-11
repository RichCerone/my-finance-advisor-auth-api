from fastapi import FastAPI, HTTPException, status
from src.documentation.docs import *
from src.libs.api_models.Token import Token
from src.libs.api_models.Credentials import Credentials
from src.libs.token_helper.TokenHelper import TokenHelper
from src.db_service.DbService import DbService, DbOptions

# Start API.
app = FastAPI(
    title=app_title,
    description=description,
    version=version,
    openapi_tags=tags_metadata
)

#Initialize environment variables.
# TODO: Need to pass these via environment variables.
SECRET_KEY = ""
ALGORITHM = ""
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ENDPOINT = ""
KEY = ""
DATABASE_ID = ""
CONTAINER_ID = ""

# Initialize services.
token_helper = TokenHelper(SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES)

db_options = DbOptions(
    ENDPOINT, 
    KEY,
    DATABASE_ID,
    CONTAINER_ID
)
users_db = DbService(db_options)

# End of service initialization.

@app.post("/token/", response_model=Token, tags=["authorization"])
async def create_token(credentials: Credentials):
    """
    Creates a new token for API access.

    Parameters
    ----------
    credentials: Credentials
        Username and password to access the API.

    Returns
    -------
    Token
        
        token required for access.
    """

    data = { "sub": credentials.username }
    token = token_helper.create_access_token(data)
    auth_token = Token(
        token = token,
        token_type="bearer"
    )

    return auth_token
