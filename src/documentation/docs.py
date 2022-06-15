__all__ = [
    "app_title",
    "description",
    "version",
    "tags_metadata",
    "create_token_responses",
    "create_user_responses"
]

app_title = "My Finance Advisor Auth API"
version = "0.0.1-alpha"

description = """
<strong>This is the My Finance Advisor Authorization API. It handles actions such as: <strong>
### - Authorization
### - User Creation
"""

tags_metadata = [
    {
        "name": "authorization",
        "description": "Authorizes user access."
    },
    {
        "name": "users",
        "description": "Users in the system."
    }
]

create_token_responses = {
   400: {
        "description": "Credentials are invalid.", 
        "content": {
                "application/json": {
                    "example": {"status_code": 0, "detail": "string"}
                }
            }
        },
   401: {
        "description": "Access Denied.",
        "content": {
            "application/json": {
                "example": {"status_code": 0, "detail": "string"}
            }
        }
        },
   404: {
            "description": "User not found.",
            "content": {
                "application/json": {
                    "example": {"status_code": 0, "detail": "string"}
                }
            }
        },
   500: {
            "description": "Error occurred generating the token or unexpected error.",
            "content": {
                "application/json": {
                    "example": {"status_code": 0, "detail": "string"}
                }
            }
        }
}

create_user_responses = {
    400: {
            "description": "Credentials are invalid.",
            "content": {
                "application/json": {
                    "example": {"status_code": 0, "detail": "string"}
                }
            }
        },
    403: {
        "description": "Unauthorized.",
        "content": {
                "application/json": {
                    "example": {"status_code": 0, "detail": "string"}
                }
            }
        },
    409: {
        "description": "User already exists in the database.",
        "content": {
                "application/json": {
                    "example": {"status_code": 0, "detail": "string"}
                }
            }
        },
    500: {
        "description": "Unexpected error occurred.",
        "content": {
                "application/json": {
                    "example": {"status_code": 0, "detail": "string"}
                }
            }
        }
}