import ast


class TypingVisitor(ast.NodeVisitor):
    def __init__(self):
        self.something = 1

    def visit_Return(self, node: ast.Return):
        print("Return node visited")

    def visit_FunctionDef(self, node: ast.FunctionDef):
        print("Function def node visited")