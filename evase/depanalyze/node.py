import ast
from typing import List, Union, Collection

import networkx as nx


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
                if name == 'app.route' or name == 'bp.route':
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
    def __init__(self, module_name, assignments: Collection[ast.Assign] = None,
                 injection_vars: Collection[ast.Name] = None,
                 func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef] = None, from_node: ast.Call = None):

        self.__module_name: str = module_name
        self.__assignments: Collection[ast.Assign] = assignments
        if self.__assignments is None:
            self.__assignments = []

        self.__injection_vars = injection_vars
        if self.__injection_vars is None:
            self.__injection_vars = set()

        self.__func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef] = func_node

        self.__from_node: ast.Call = from_node

        if self.__func_node is not None:
            if is_flask_api_function(func_node) or is_django_api_function(func_node):
                self.is_endpoint = True
            else:
                self.is_endpoint = False
        else:
            self.is_endpoint = False

    def get_func_node(self):
        return self.__func_node

    def get_assignments(self):
        return self.__assignments

    def get_injection_vars(self):
        return self.__injection_vars

    def get_module_name(self):
        return self.__module_name

    def set_injection_vars(self, injection_vars):
        self.__injection_vars = injection_vars

    def __str__(self):
        if self.get_func_node() is None:
            return f'{self.get_module_name()}:*'
        else:
            return f'{self.get_module_name()}:{self.get_func_node().name}'

    def __repr__(self):
        if self.get_func_node() is None:
            if self.__from_node is None:
                return f'{self.get_module_name()}:*={len(self.get_assignments())}'
            return f'{self.get_module_name()}:*;{ast.unparse(self.__from_node.func)}={len(self.get_assignments())}'
        if self.__from_node is None:
            return f'{self.get_module_name()}:{self.get_func_node().name}={len(self.get_assignments())}'
        return f'{self.get_module_name()}:{self.get_func_node().name};{ast.unparse(self.__from_node.func)}={len(self.get_assignments())}'


    def get_node_props(self) -> dict:

        assignment_lines = []
        for assign in self.get_assignments():

            if not isinstance(assign, ast.Assign): continue

            assignment_lines.append({
                'start': assign.lineno,
                'end': assign.end_lineno,
            })

        func = {}
        if self.get_func_node():
            func = {
                'endpoint': self.is_endpoint,
                'start': self.__func_node.lineno,
                'end': self.__func_node.end_lineno,
                'name': self.__func_node.name
            }

        from_node = {}
        if self.__from_node is not None:
            from_node = {
                'start': self.__from_node.lineno,
                'end': self.__from_node.end_lineno,
                'name': ast.unparse(self.__from_node.func)
            }

        return {
            'vars': list(self.get_injection_vars()),
            'assignments': assignment_lines,
            'func_scope': func,
            'calls_vulnerable': from_node,
            'endpoint': self.is_endpoint
        }

    def add_to_graph(self, graph):
        if not graph.has_node(str(self)):

            props = self.get_node_props()

            graph.add_node(str(self), **{
                '__node_data': [
                    props
                ]
            })
        else:
            nodes_data = nx.get_node_attributes(graph, '__node_data')
            data = nodes_data[str(self)]

            props = self.get_node_props()

            data.append(props)

            nx.set_node_attributes(graph, {str(self): data}, name='__node_data')

    def __eq__(self, other):
        if isinstance(other, Node):
            return all(
                [
                    self.get_module_name() == other.get_module_name(),
                    self.get_func_node() == other.get_func_node(),
                    self.__from_node == other.__from_node
                ]
            )
        return False

    def __hash__(self):
        return hash(self.__repr__())
