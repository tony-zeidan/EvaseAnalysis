import user_db_handler


def add_user_to_db(username: str, password: str, handler: user_db_handler) -> str:
    """
    Adds a new user to the database

    :param username: The username for the user
    :param password: The password of the user
    :return: Add user message
    """
    result = handler.handle_new_user(username, password)
    return result


def get_user_from_db(username: str, handler: user_db_handler) -> list:
    """
    Gets a user from the SQLite database.
    This function is susceptible to SQL injection.

    :param username: The username
    :return: The user information
    """
    result = handler.handle_get_user(username)
    return result
