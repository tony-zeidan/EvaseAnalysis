import sqlite3
import string

def vulnerable_executor(password: string, a: string, c: string):
    arr = []
    b, d = a, password
    d = ""
    g = c
    if a == 5:
        f = password
        if b == 2:
            d = f

    for b in arr:
        d = c

    cur = sqlite3.cursor()
    cur.execute('''SELECT admin FROM users WHERE username = ''' + d, password)


def vulnerable_wrapper():
    a = 2
    vulnerable_executor("a" + a, "b", "c")

