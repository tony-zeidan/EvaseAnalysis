import sqlite3 as sq

def add_user_to_db(username: str, password: str) -> str:
    """
    Adds a new user to the database

    :param username: The username for the user
    :param password: The password of the user
    :return: Add user message
    """
    conn = sq.connect('sample.db')
    conn.execute(f"INSERT INTO USER ( userName, password) VALUES ('{username}', '{password}')")
    conn.commit()
    conn.close()
    return "user [" + username + "] added auccess"


def get_user_from_db(username: str) -> list:
    """
    Gets a user from the SQLite database.
    This function is susceptible to SQL injection.

    :param username: The username
    :return: The user information
    """
    conn = sq.connect('sample.db')
    print(username)
    curser = conn.execute(f"SELECT userName, password from USER where userName = '{username}'")
    userInfo = []
    for row in curser:
        data = [row[0], row[1]]
        userInfo.append(data)
        print("ID = ", row[0])
        print("userName = ", row[1])

    conn.close()
    return userInfo
