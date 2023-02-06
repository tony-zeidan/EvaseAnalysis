from pprint import pprint

def pretty_printer(ugly_str: str):
    pprint(ugly_str)

class Exec:

    @classmethod
    def exec(cls, st):
        print(st)