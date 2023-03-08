from vul import add_user_to_db as y, get_user_from_db as x


def add_user_wrapper(username: str, password: str) -> str:
    """
    Adds a user to the system.
    Wrapper for database system function.

    :param username: Username of the new user
    :param password: Password of the new user
    :return: Success message
    """

    return y(username, password)


def get_user_wrapper(username: str) -> list:
    """
    Retrieves a user from the system.
    Wrapper for database system function.

    :param username: The username of the user to get
    :return: Any user information retrieved
    """
    a = username
    return x(a)
