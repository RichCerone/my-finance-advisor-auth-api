import json
import src.libs.model_validation.ModelValidators as ModelValidators
import logging as logger

from fastapi import Depends, FastAPI, HTTPException
from jose import JWTError
from src.exceptions.UserNotFoundError import UserNotFoundError
from src.exceptions.AccessDeniedError import AccessDeniedError
from src.documentation.docs import *
from src.libs.api_models.Token import Token
from src.libs.api_models.Credentials import Credentials
from src.token_helper.TokenHelper import TokenHelper
from src.hashing.HashingHelper import BCryptHelper
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
def init_token_helper():
    return TokenHelper(SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES)

def init_bcrypt_helper():
    return BCryptHelper()

def init_users_db():
    db_options = DbOptions(
        ENDPOINT, 
        KEY,
        DATABASE_ID,
        CONTAINER_ID
    )

    users_db = DbService(db_options)
    users_db.connect()

    return users_db

# End of service initialization.

@app.post("/token/", status_code=201, response_model=Token, tags=["authorization"])
def create_token(credentials: Credentials, 
users_db: DbService = Depends(init_users_db), 
token_helper: TokenHelper = Depends(init_token_helper),
bcrypt_helper: BCryptHelper = Depends(init_bcrypt_helper)):
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
        logger.info("Validating credential parameters.")

        ModelValidators.validateCredentials(credentials)
        
        logger.info("Credential parameters are valid.")
        logger.info("Checking if username '{0}' is authorized.")

        user = User(credentials.username, credentials.password)
        user_json = users_db.get(user.id, user.user)
        
        if (user_json is None):
            logger.warning("User '{0}' is not authorized for access.")
            raise UserNotFoundError("User '{0}' does not exist.".format(user.user))

        user_payload = json.loads(user_json)

        logger.info("User '{0}' is authorized for access.".format(user.user))
        logger.info("Validating password.")

        if not bcrypt_helper.verify_password(user.password, user_payload["password"]):
            logger.warning("Password is invalid.")
            raise AccessDeniedError()
            
        logger.info("Password is valid.")
        logger.info("Generating token.")

        data = { "sub": credentials.username }
        token = token_helper.create_access_token(data)
        auth_token = Token(
            token = token,
            token_type="bearer"
        )

        logger.info("Token generated.")

        return auth_token

    except Exception as e:
        logger.exception("POST Exception on 'create_token' -> {0}".format(e))

        if e.__class__ == JWTError:
            raise HTTPException(status_code=500, detail="An error occurred generating the token.")
        elif e.__class__ == ValueError:
            raise HTTPException(status_code=400, detail=str(e))
        elif e.__class__ == AccessDeniedError:
            raise HTTPException(status_code=401, detail="Access Denied.")
        elif e.__class__ == UserNotFoundError:
            raise HTTPException(status_code=404, detail=e.message)
        else:
            raise HTTPException(status_code=500, detail="An unexpected error occurred.")