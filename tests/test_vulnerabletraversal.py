import ast
import testutil

if __name__ == '__main__':
    import testutil
    r = testutil.vul1_filename
    with open(r, 'r') as f:
        tree = ast.parse(f.read())
        print(tree.body[0].decorator_list[0].__dict__)
        print(tree.body[0].decorator_list[0].func.attr)