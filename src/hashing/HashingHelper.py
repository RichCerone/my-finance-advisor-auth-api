from passlib.context import CryptContext

class BCryptHelper():
    """
    Helps with hashing using bcrypt 
    """

    def __init__(self):
        pass
    

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verifies the password.

        Parameters
        ----------
        password: str
            The password to verify.

        hashed_password: str
            The hashed password to verify against.

        Returns
        -------
        bool
            True if valid or false if not.
        """

        passwordContext = self.__create_password_context()
        return passwordContext.verify(password, hashed_password)


    def get_password_hash(self, password: str) -> str:
        """
        Gets the password hash with the given password.

        Parameters
        ----------
        password: str
            The password to hash.

        Returns
        -------
        str
            The password hash.
        """

        passwordContext = self.__create_password_context()
        return passwordContext.hash(password)


    # Creates a crypto context for hashing using the bcrypt algorithm.
    def __create_password_context(self) -> CryptContext:
        return CryptContext(schemes=["bcrypt"], deprecated="auto")