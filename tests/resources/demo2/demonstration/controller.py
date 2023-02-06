from model import check_DB as a
import model as a


def check_DB(f):
    b = f
    c = "3"
    a.vulnerable_executor(b, b, "c")


def check_DB_wrapper(a):
    check_DB(a)
