import ast
from typing import Collection, Dict
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


class CodeTraversalNode:
    def __init__(
            self,
            module_name: str,
            assignments: Collection[ast.Assign] = None,
            variables: Collection[ast.Name] = None,
            func_node: ast.FunctionType = None, from_node: ast.Call = None
    ):
        """
        This class represents a data container for traversal of code.
        It is currently used in the traversal for the SQL injection breadth-first search algorithm, but can be used for more.

        :param module_name: The name of the module that the data of this node appears in
        :param assignments: The collection of assignment nodes collected for this traversal node
        :param variables: The collection of variables collected for this traversal node
        :param func_node: The ast node representing the function that the data for this node appeared in
        :param from_node: A key function node that the contents of the node invoke
        """

        self.__module_name: str = module_name

        # assignments
        self.__assignments: Collection[ast.Assign] = assignments
        if self.__assignments is None:
            self.__assignments = []

        # variables
        self.__variables = variables
        if self.__variables is None:
            self.__variables = set()

        self.__func_node: ast.FunctionType = func_node
        self.__from_node: ast.Call = from_node

        # check if the function node is an endpoint or not
        if self.__func_node is not None:
            if is_flask_api_function(func_node) or is_django_api_function(func_node):
                self.is_endpoint = True
            else:
                self.is_endpoint = False
        else:
            self.is_endpoint = False

    def get_func_node(self) -> ast.FunctionType:
        """
        Get the ast function node of this node.

        :return:
        """

        return self.__func_node

    def get_assignments(self):
        """
        Retrieve the set of assignment-nodes for this node.

        :return: The assignment nodes for the node
        """

        return self.__assignments

    def get_variables(self):
        """
        Get the set of variables to look present in this node.

        :return: The variables of the node
        """

        return self.__variables

    def get_module_name(self):
        """
        Retrieve the module name for this node.

        :return: The module name
        """

        return self.__module_name

    def set_variables(self, injection_vars):
        """
        Set the variables to look for.

        :param injection_vars: The set of injection related variables to look for
        """

        self.__variables = injection_vars

    def __str__(self) -> str:
        """
        Retrieve a string representation of the node.

        :return: String representation
        """

        if self.get_func_node() is None:
            return f'{self.get_module_name()}:*'
        else:
            return f'{self.get_module_name()}:{self.get_func_node().name}'

    def __repr__(self) -> str:
        """
        Retrieve a more comprehensive representation of the node.

        :return: Detailed string representation
        """

        if self.get_func_node() is None:
            if self.__from_node is None:
                return f'{self.get_module_name()}:*={len(self.get_assignments())}'
            return f'{self.get_module_name()}:*;{ast.unparse(self.__from_node.func)}={len(self.get_assignments())}'
        if self.__from_node is None:
            return f'{self.get_module_name()}:{self.get_func_node().name}={len(self.get_assignments())}'
        return f'{self.get_module_name()}:{self.get_func_node().name};{ast.unparse(self.__from_node.func)}={len(self.get_assignments())}'

    def get_node_props(self) -> Dict:
        """
        Return the properties of this node in a dictionary for adding to the graph.

        :return: The properties of the node
        """

        # collect assignment lines
        assignment_lines = []
        for assign in self.get_assignments():

            if not isinstance(assign, ast.Assign): continue

            assignment_lines.append({
                'start': assign.lineno,
                'end': assign.end_lineno,
            })

        # collect the function node
        func = {}
        if self.get_func_node():
            func = {
                'endpoint': self.is_endpoint,
                'start': self.__func_node.lineno,
                'end': self.__func_node.end_lineno,
                'name': self.__func_node.name
            }

        # collect the calls vulnerable node
        from_node = {}
        if self.__from_node is not None:
            from_node = {
                'start': self.__from_node.lineno,
                'end': self.__from_node.end_lineno,
                'name': ast.unparse(self.__from_node.func)
            }

        return {
            'vars': list(self.get_variables()),
            'assignments': assignment_lines,
            'func_scope': func,
            'calls_vulnerable': from_node,
            'endpoint': self.is_endpoint
        }

    def add_to_graph(self, graph):
        """
        Adds this node representation to a NetworkX graph.
        In the case that the node isn't present in the graph, a node is added with a __node_data property.
        In the case that the node is present in the graph, the __node_data property has the properties of the
        current node appended to it. This only occurs when the node properties aren't an exact copy.

        :param graph: The graph to add to
        """

        # if the graph doesn't already have the node, simply add it
        if not graph.has_node(str(self)):

            props = self.get_node_props()

            # add with props
            graph.add_node(str(self), **{
                '__node_data': [
                    props
                ]
            })

        # if the node is already in the graph, update properties
        else:

            # fetch current properties
            nodes_data = nx.get_node_attributes(graph, '__node_data')

            try:
                data = nodes_data[str(self)]

                props = self.get_node_props()

                # don't allow duplicate graph data
                if len(data) != 0:
                    for item in data:
                        if all([v == item[k] for k, v in props.items()]):
                            return

                # append and update
                data.append(props)
                nx.set_node_attributes(graph, {str(self): data}, name='__node_data')
            except KeyError:
                pass

    def __eq__(self, other):
        """
        Check for equality between nodes.

        :param other: The other node to check
        :return: Whether they are equal or not
        """

        if isinstance(other, CodeTraversalNode):
            return all(
                [
                    self.get_module_name() == other.get_module_name(),
                    self.get_func_node() == other.get_func_node(),
                    ast.unparse(self.__from_node.func) == ast.unparse(other.__from_node.func)
                ]
            )
        return False

    def __hash__(self):
        """
        Each node can be hashed.

        :return: The hash of the current node
        """

        return hash(self.__repr__())
