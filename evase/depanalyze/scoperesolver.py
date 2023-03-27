import ast
from _ast import AST


class ScopeResolver(ast.NodeTransformer):

    def __init__(self):
        """
        A class

        """

        self.class_stack = []
        self.func = None

    def reset(self):
        self.class_stack.clear()
        self.func = None

    def visit_ClassDef(self, node: ast.ClassDef):
        self.class_stack.append(node.name)
        super().generic_visit(node)
        self.class_stack.pop()
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.func = node
        newname = '.'.join(self.class_stack)
        setattr(node, 'parent_classes', list(reversed(self.class_stack.copy())))
        if len(self.class_stack) > 0:
            node.name = f'{newname}.{node.name}'
        super().generic_visit(node)
        return node

    def generic_visit(self, node: AST):
        super().generic_visit(node)
        return node;