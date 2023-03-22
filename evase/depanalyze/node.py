import ast
from typing import List, Union, Collection


def is_flask_api_function(func_node: ast.FunctionDef):
    """
    Determines if a function definition approximates one that is used for APIs in Flask.
    Checks the decorators of the function definition.

    :param func_node: The function definition node
    :return: Whether the definition node represents a definition for Flask API
    """
    for dec in func_node.decorator_list:
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Attribute):
                name = f'{dec.func.value.id}.{dec.func.attr}'
                if name == 'app.route':
                    return True
    return False


def is_django_api_function(func_node: ast.FunctionDef):
    """
    Determines if a function definition approximates one that is used for APIs in Django.
    Checks the decorators of the function definition.

    :param func_node: The function definition node
    :return: Whether the definition node represents a definition for Django API
    """
    for dec in func_node.decorator_list:
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                if dec.func.id == "app_view":
                    return True
    return False


class Node:
    def __init__(self, func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef], assignments: Collection[ast.Assign],
                 injection_vars, module_name):
        self._func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef] = func_node
        self._assignments: Collection[ast.Assign] = assignments
        self._injection_vars = injection_vars
        self._module_name: str = module_name

        if is_flask_api_function(func_node) or is_django_api_function(func_node):
            self.is_endpoint = True
        else:
            self.is_endpoint = False

    def get_func_node(self):
        return self._func_node

    def get_assignments(self):
        return self._assignments

    def get_injection_vars(self):
        return self._injection_vars

    def get_module_name(self):
        return self._module_name

    def set_injection_vars(self, injection_vars):
        self._injection_vars = injection_vars

    def __str__(self):
        return f'{self.get_module_name()}.{self.get_func_node().name}'

    def __repr__(self):
        return f'{self.get_module_name()} {self.get_func_node().name} {len(self.get_assignments())}'

    def get_node_props(self) -> dict:

        assignment_lines = []
        for assign in self.get_assignments():
            assignment_lines.append({
                'start': assign.lineno,
                'end': assign.end_lineno,
                'offset_start': assign.col_offset,
                'offset_end': assign.end_col_offset,
                'type_comment': assign.type_comment
            })

        func = {
            'endpoint': self.is_endpoint,
            'start': self._func_node.lineno,
            'end': self._func_node.end_lineno,
            'offset_start': self._func_node.col_offset,
            'offset_end': self._func_node.end_col_offset,
            'name': self._func_node.name
        }

        return {
            'vars': list(self.get_injection_vars()),
            'assignments': assignment_lines,
            'func': func,
            'endpoint': self.is_endpoint
        }

    def add_to_graph(self, graph):
        graph.add_node(str(self), **self.get_node_props())
