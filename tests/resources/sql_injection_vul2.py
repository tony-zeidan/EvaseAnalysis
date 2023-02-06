def amdinExec(username):
    query = "SELECT admin FROM users WHERE username = '" + username
    cursor.execute(query)
