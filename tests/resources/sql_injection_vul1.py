
@app.route('/upload')
def amdinExec(username):
    cursor.execute("SELECT admin FROM users WHERE username = '" + username)
