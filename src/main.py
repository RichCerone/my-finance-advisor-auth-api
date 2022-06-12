import src.libs.model_validation.ModelValidators as ModelValidators
import logging as logger

from fastapi import FastAPI, HTTPException
from jose import JWTError
from src.exceptions.UserNotFoundError import UserNotFoundError
from src.documentation.docs import *
from src.libs.api_models.Token import Token
from src.libs.api_models.Credentials import Credentials
from src.libs.token_helper.TokenHelper import TokenHelper
from src.db_service.DbService import DbService, DbOptions
from src.data_models.User import User

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
users_db.connect()

# End of service initialization.

@app.post("/token/", status_code=201, response_model=Token, tags=["authorization"])
def create_token(credentials: Credentials):
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
    try:
        ModelValidators.validateCredentials(credentials)
        
        user = User(credentials.username, credentials.password)
        user_json = users_db.get(user.id, user.user)
        
        if (user_json is None):
            raise UserNotFoundError("User '{0}' does not exist.".format(user.user))

        data = { "sub": credentials.username }
        token = token_helper.create_access_token(data)
        auth_token = Token(
            token = token,
            token_type="bearer"
        )

        return auth_token

    except Exception as e:
        logger.exception("POST Exception on 'create_token' -> {0}".format(e))

        if e.__class__ == JWTError:
            raise HTTPException(status_code=500, detail="An error occurred generating the token.")
        elif e.__class__ == ValueError:
            raise HTTPException(status_code=400, detail=str(e))
        elif e.__class__ == UserNotFoundError:
            raise HTTPException(status_code=404, detail=e.message)
        else:
            raise HTTPException(status_code=500, detail="An unexpected error occurred.")