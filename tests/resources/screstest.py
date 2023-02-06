

class Executor:
    def __init__(self):
        self.username = None

    def amdinExec(self, username):
        cursor.execute("SELECT admin FROM users WHERE username = %s'", (username))

def adminExec(username):
    cursor.execute("SELECT admin FROM users WHERE username = %s'", (username))
