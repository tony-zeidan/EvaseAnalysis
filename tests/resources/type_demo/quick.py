import ast

with open(r'D:\work\programming\sql-injection-demo\backend\app.py', 'r') as file:
    tree = ast.parse(file.read())
    print(ast.dump(tree, indent=2))