from datetime import datetime, timedelta
from jose import JWTError, jwt
from src.exceptions.CredentialNotInJwtError import CredentialNotInJwtError

class TokenHelper():
    """
    Helps generate and authorize tokens.
    """

    def __init__(self, secret_key: str, algo: str, access_token_expire_minutes: int=30):
        """
        Parameters
        ----------
        secret_key: str
            The secret key used for signing the token.

        algo: str
            The algorithm to use for signing the token.

        access_token_expire_minutes: int
            Time in minutes the token expires. Default is 30 minutes.

        Raises
        ------
        ValueError
            Raised if the secret key or algorithm are undefined.
        """

        if secret_key is None or secret_key.isspace():
            raise ValueError("secret_key must be defined.")
        
        elif algo is None or algo.isspace():
            raise ValueError("algo must be defined.")

        self.secret_key = secret_key
        self.algo = algo
        self.access_token_expire_minutes = access_token_expire_minutes


    def create_access_token(self, data: dict, expires: bool=True) -> any:
        """
        Creates the access token.

        Parameters
        ----------
        data: dict
            The data to encode into the token.

        expires: bool
            Whether this token should expire.

        Returns
        -------
        any
            The token.

        Raises
        -----
        JWTError:
            Raised if the token cannot be encoded.

        Exception:
            Raised if an unexpected error occurs.
        """
        try:
            to_encode = data.copy()
            if expires:
                expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
                to_encode.update({ "exp": expire })

            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algo)
            return encoded_jwt

        except JWTError as e:
            raise
        except Exception as e:
            raise

    def decode_access_token(self, token) -> str:
        """
        Decodes the access token.

        Parameters
        ----------
        token: str
            The token to decode.

        Raises
        -----
        JWTError:
            Raised if the token cannot be decoded.

        Exception:
            Raised if an unexpected error occurs.

        Returns
        -------
        str:
            The username in the token.
        """
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algo])
            username: str = payload.get("sub")
            if username is None or username.isspace():
                raise CredentialNotInJwtError("Expected 'sub' credential in the payload, but it was not found.")
        except JWTError as e:
            raise
        except Exception as e:
            raise
        
        return username
    
    
    