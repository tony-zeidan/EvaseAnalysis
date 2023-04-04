import ast
from typing import List


class ScopeResolver(ast.NodeTransformer):

    def __init__(self, module_name: str = None):
        """
        A class to help resolve the parent nodes of certain functions.
        """
        self._module_name: str = module_name
        self._class_stack: List[ast.ClassDef] = []
        self._funcs: List[ast.FunctionType] = []

    @property
    def module_name(self) -> str:
        """
        Retrieve the module name.

        :return: The module name of the module that this resolver is linked to
        """
        return self._module_name

    @module_name.setter
    def module_name(self, module_name: str):
        """
        Set the name of the module that this resolver is linked to

        :param module_name: The name of the module that this resolver is linked to
        """
        if module_name is None:
            raise ValueError("Can't set the name of the module to none!")

        self._module_name = module_name

    def reset(self):
        """
        Reset the scope resolver back to original state for reuse.
        """
        self._module_name = None
        self._class_stack.clear()
        self._funcs.clear()

    def visit_Module(self, node: ast.Module):
        """
        Set the name of the module ast node.

        :param node: The module definition node
        :return: The module definition node
        """
        setattr(node, 'module_name', self._module_name)
        super().generic_visit(node)
        return node

    def visit_ClassDef(self, node: ast.ClassDef):
        """
        When visiting a class definition, add the name to the class stack.

        :param node: The class definition node
        :return: The class definition node
        """
        print("CLASS ADDED")
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
            print("NEWNAME", node.name)
        self.funcs.append(node)

        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """
        When visiting a function, take the current stack of classes visited and
        change the name of the function to incorporate what class it's located in.

        :param node: The function definition node
        :return: The function definition with altered name
        """
        super().generic_visit(node)
        return self.visit_Function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        """
        When visiting a function, take the current stack of classes visited and
        change the name of the function to incorporate what class it's located in.

        :param node: The function definition node
        :return: The function definition with altered name
        """
        super().generic_visit(node)
        return self.visit_Function(node)

    @property
    def funcs(self) -> List[ast.FunctionType]:
        """
        Retrieve a list of functions visited

        :return: Function nodes visited
        """

        return self._funcs.copy()
