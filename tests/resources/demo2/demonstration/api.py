from flask import Flask

from controller import check_DB_wrapper

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def file_upload_hook(a):
    check_DB_wrapper(a)