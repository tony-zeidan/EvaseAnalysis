import sqlite3

def handle_new_user(username: str, password: str) -> str:
    conn = sqlite3.connect('sample.db')
    conn.execute(f"INSERT INTO USER ( userName, password) VALUES ('{username}', '{password}')")
    conn.commit()
    conn.close()
    return "user [" + username + "] added auccess"

def handle_get_user(username: str) -> str: 
    conn = sqlite3.connect('sample.db')
    print(username)
    curser = conn.execute(f"SELECT userName, password from USER where userName = '{username}'")
    userInfo = []
    for row in curser:
        data = [row[0], row[1]]
        userInfo.append(data)
        print("userName = ", row[0])
        print("password = ", row[1])
    
    print(userInfo)

    conn.close()
    return userInfo