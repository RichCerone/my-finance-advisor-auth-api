_collection_name = "user"

class User(object):
    """
    Holds the user data.
    """

    def __init__(self, user: str, password: str):
        """
        Creates a new User.

        Parameters
        ----------
        user: str
            The username. Spaces will be stripped.
        
        password: str
            The hashed password for this user.

        Raises
        ------
        ValueError
            Raised if the user or password is not defined.
        """
        if not user or user.isspace():
            raise ValueError("user must be defined.")
        elif not password or password.isspace():
            raise ValueError("password must be defined.")

        self.id = "{0}::{1}".format(_collection_name, "".join(user.split()).lower())
        self.user = user
        self.password = password
        self._rid = "",
        self._self = ""
        self._etag = "",
        self._attachments = "",
        self._ts = 0
    
    def create_id(self, user: str) -> str:
        """
        Creates a new id for the object.

        Parameters
        ----------
        user: str
            The user which will be the partial makeup of the id.

        Returns
        -------
        str
            The new id.

        Raises
        ------
        ValueError
            Raised if the parameter given is invalid.

        Remarks
        -------
        When calling this method, the id and user attributes for this class will also be assigned
        with the new id created. There is no need to assign the new id to 'self.id' nor 'self.user'.
        """

        if not user or user.isspace():
            raise ValueError("'user' must be defined.")

        self.user = "".join(user.split())
        self.id = "{0}::{1}".format(_collection_name, self.user.lower())

        return self.id

    def __str__(self) -> str:
        return "'id': '{0}' | 'user': '{1}'".format(self.id, self.user)
