from os import *
import sqlite3 as sql3

class Exec:
    def amdinExec(self, username, a, c):
        password, c, c = a, c, "2"
        c = "a"+a + c

        cursor = sql3.Cursor()
        cursor.execute("SELECT admin FROM users WHERE username = '" + username+ " here" + password, "h", password)


def amdinExec(username, a, c):
    password, c, c = a, c, "2"
    c = "a"+a + c

    cursor = sql3.Cursor()
    cursor.execute("SELECT admin FROM users WHERE username = '" + username+ " here" + password, "h", password)