import sqlite3 as sql3


def main_run():
    cursor_obj = get_cursor()
    cursor_obj.execute()


def get_cursor():
    return sql3.Cursor()