import json
import src.libs.model_validation.ModelValidators as ModelValidators
import logging as logger

from fastapi import Depends, FastAPI, Request, HTTPException
from jose import JWTError
from src.exceptions.UserNotFoundError import UserNotFoundError
from src.exceptions.UserAlreadyExistsError import UserAlreadyExists
from src.exceptions.AccessDeniedError import AccessDeniedError
from src.authorization.JwtBearer import inject_jwt_bearer
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
# TODO: Does it make sense to wrap these into its own package to re-use across APIs?
def init_token_helper() -> TokenHelper:
    """
    Initializes a token helper service.

    Returns
    -------
    TokenHelper
        The token helper service.
    """

    return TokenHelper(SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES)


def init_bcrypt_helper() -> BCryptHelper:
    """
    Initializes a bcrypt helper service.

    Returns
    -------
    BCryptHelper
        The bcrypt helper services.
    """

    return BCryptHelper()


def init_users_db() -> DbService:
    """
    Initializes a users database.

    Returns
    -------
    DbService
        The users database.
    """
    db_options = DbOptions(
        ENDPOINT, 
        KEY,
        DATABASE_ID,
        CONTAINER_ID
    )

    users_db = DbService(db_options)
    users_db.connect()

    return users_db


def authorize_access(request: Request) -> str:
    """
    Authorizes access based on the token

    Parameters
    ----------
    request: Request
        The incoming HTTP request.

    Raises
    ------
    HttpException
        403 - if token is not authorized.
        500 - if an error occurs processing the token.

    Returns
    -------
    str
        The username in the token.
    """

    try:
        logger.info("Getting authorization token from header 'Authorization'.")
        
        token = request.headers["Authorization"].split()[1]

        logger.info("Token retrieved.")
        logger.debug("Initializing token helper service to decode token.")
        
        token_helper = init_token_helper()
        
        logger.debug("Token helper service initialized.")
        logger.info("Decoding token.")

        user_in_token = token_helper.decode_access_token(token)

        logger.info("Token decoded. User: '{0}'".format(user_in_token))
        logger.debug("Initializing users database for user authorization.")

        users_db = init_users_db()
        user = User(user_in_token, "_") # Note: '_' is used because we need to pass a non empty string, but also don't need the password.

        logger.info("Validating user '{0}'".format(user_in_token))

        if users_db.get(user.id, user.user) is None:
            logger.warning("User '{0}' is not authorized.".format(user_in_token))
            raise HTTPException(403, "Unauthorized.")

        logger.info("User '{0}' is authorized access.".format(user_in_token))

        return user_in_token

    except Exception as e:
        logger.exception("authorize_access exception -> An error occurred processing the token: {0}".format(e))
        raise HTTPException(500, "Authorization token cannot be processed.")


def credential_validation(credentials: Credentials):
    """
    Provides validation on the passed credentials.

    Parameters
    ----------
    credentials: Credentials
        Credentials to validate.

    Raises
    ------
    HTTPException
        400 - Raised if the parameters are invalid.
    """

    try:
        logger.info("Validating credential parameters.")

        ModelValidators.validate_credentials(credentials)
        
        logger.info("Credential parameters are valid.")
    
    except ValueError as e:
        logger.exception("credential_validation exception -> Error occurred validating credentials: {0}".format(e))
        raise HTTPException(400, str(e))

# End of service initialization.

@app.post("/token/", status_code=201, responses=create_token_responses, dependencies=[Depends(credential_validation)], response_model=Token, tags=["authorization"])
def create_token(credentials: Credentials, 
users_db: DbService = Depends(init_users_db), 
token_helper: TokenHelper = Depends(init_token_helper),
bcrypt_helper: BCryptHelper = Depends(init_bcrypt_helper)):
    """
    Creates a new token for API access.
    """

    try:
        logger.info("Checking if username '{0}' is authorized.")

        user = User(credentials.username, credentials.password)
        user_json = users_db.get(user.id, user.user)
        
        if user_json is None:
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
        logger.exception("POST exception on 'create_token' -> {0}".format(e))

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


@app.post("/users/", status_code=201, responses=create_user_responses, dependencies=[Depends(inject_jwt_bearer), Depends(credential_validation)], response_model=Credentials, tags=["users"])
def create_user(credentials: Credentials, 
users_db: DbService = Depends(init_users_db), 
bcrypt_helper: BCryptHelper = Depends(init_bcrypt_helper),
user: str = Depends(authorize_access)):
    """
    Creates a new user.
    """

    try:
        logger.info("User '{0}' is creating a new user.".format(user))
        logger.debug("Creating user: '{0}'".format(credentials.username))        
        logger.debug("Hashing password.")

        credentials.password = bcrypt_helper.get_password_hash(credentials.password)
        
        logger.debug("Password hashed.")
        logger.debug("Checking if user '{0}' already exists.".format(credentials.username))

        user_for_db = User(credentials.username, credentials.password)
        if users_db.get(user_for_db.id, user_for_db.user) is not None:
            logger.warning("User '{0}' already exists in the database.".format(user_for_db.user))
            raise UserAlreadyExists("This username is already taken: '{0}'".format(credentials.username))

        logger.debug("User '{0}' does not exist already in the database.".format(credentials.username))
        logger.debug("Upserting user: '{0}'".format(credentials.username))

        user_json = users_db.upsert(user_for_db.__dict__)
        user_payload = json.loads(user_json)

        logger.info("User '{0}' created.".format(user_payload["user"]))

        return credentials

    except Exception as e:
        logger.exception("POST exception on 'create_user' -> {0}".format(e))
        
        if e.__class__ == ValueError:
            raise HTTPException(status_code=400, detail=str(e))
 
        elif e.__class__ == UserAlreadyExists:
            raise HTTPException(status_code=409, detail=e.message)

        else:
            raise HTTPException(status_code=500, detail="An unexpected error occurred.")
