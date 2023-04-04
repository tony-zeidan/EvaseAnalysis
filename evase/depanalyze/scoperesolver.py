import ast
from typing import List


class ScopeResolver(ast.NodeTransformer):

    def __init__(self):
        """
        A class to help resolve the parent nodes of certain functions.
        """

        self._class_stack: List[ast.ClassDef] = []
        self._funcs: List[ast.FunctionType] = []

    def reset(self):
        """
        Reset the scope resolver back to original state for reuse.
        """

        self._class_stack.clear()
        self._funcs.clear()

    def visit_ClassDef(self, node: ast.ClassDef):
        """
        When visiting a class definition, add the name to the class stack.

        :param node: The class definition node
        :return: The class definition node
        """

        self._class_stack.append(node)
        super().generic_visit(node)
        self._class_stack.pop()
        return node

    def visit_Function(self, node: ast.FunctionType):
        """
        When visiting a function, take the current stack of classes visited and
        change the name of the function to incorporate what class it's located in.

        :param node: The function definition node
        :return: The function definition with altered name
        """

        newname = '.'.join([cls.name for cls in self._class_stack])
        setattr(node, 'parent_classes', list(reversed(self._class_stack.copy())))
        if len(self._class_stack) > 0:
            node.name = f'{newname}:{node.name}'
        self.funcs.append(node)

        super().generic_visit(node)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """
        When visiting a function, take the current stack of classes visited and
        change the name of the function to incorporate what class it's located in.

        :param node: The function definition node
        :return: The function definition with altered name
        """
        return self.visit_Function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        """
        When visiting a function, take the current stack of classes visited and
        change the name of the function to incorporate what class it's located in.

        :param node: The function definition node
        :return: The function definition with altered name
        """
        return self.visit_Function(node)

    @property
    def funcs(self) -> List[ast.FunctionType]:
        """
        Retrieve a list of functions visited

        :return: Function nodes visited
        """

        return self._funcs.copy()

    def generic_visit(self, node: ast.AST) -> ast.AST:
        """
        Overwritten generic visit function.

        :param node: Any AST node
        :return: The visited node
        """

        super().generic_visit(node)
        return node
