import ast
import os
from pathlib import Path
from typing import Tuple, TypedDict, Optional, Union, Dict, Set
import re

from evase.util.fileutil import check_path

COUNT_DOTS = re.compile(r"(from|import)\s(\.+)")  # pattern for relative imports

# custom type
DependencyMapping = TypedDict('DependencyMapping', {
    str: Tuple[str, Optional[str]]
})

LocalDependencyMapping = TypedDict('LocalDependencyMapping', {
    str: Set[Tuple[str, Optional[str]]]
})


class ModuleImportResolver(ast.NodeTransformer):
    def __init__(self):
        """
        A class that collects local and module level imports for a module.

        For this class to behave properly, it requires that the surface values to have their scopes resolved.
        It also requires that the AST of this module had its scope resolved.
        """
        self._directory = None
        self._is_surface = True
        self._surface_imports: DependencyMapping = {}
        self._local_imports: LocalDependencyMapping = {}
        self._surface_values = {}
        self._function_name = ""
        self._key = None

    @property
    def directory(self) -> Path:
        """
        Retrieve the current directory.

        :return: The directory path
        """
        return self._directory

    @directory.setter
    def directory(self, directory: Union[str, Path]):
        """
        Set the directory.
        This function will throw an error if the directory isn't valid.

        :param directory: The directory for the project
        """
        self._directory = check_path(directory, file_ok=False, file_req=False, absolute_req=False, ret_absolute=False)

    @property
    def surface_values(self):
        """
        Retrieve the surface import values.
        Ensure that these surface values have been had their scopes resolved.

        :return: The surface importable items
        """

        return self._surface_imports.copy()

    @surface_values.setter
    def surface_values(self, surface_values: Dict):
        """
        Set the current surface importable items.

        :param surface_values:
        :return:
        """
        if not isinstance(surface_values, dict):
            raise ValueError("The surface values need to be a dictionary of module names (package style) to strings "
                             "of importable items.")

        self._surface_values = surface_values

    @property
    def key(self):
        """
        Get the current key.

        :return: The current module key
        """

        return self._key

    @key.setter
    def key(self, key: str):
        """
        Set the module to search for in the project structure.

        :param key: The module key
        """

        self._key = key

    @property
    def local_dependencies(self) -> LocalDependencyMapping:
        """
        Retrieve the local level dependencies.
        It is a mapping of strings of function names to tuples of where they come from.

        e.g. in module example.py INSIDE foo()::

            def foo():
                from example2 import bar
                from example3 import baz as sam

            looks like:
            {
                'foo': {('example2:bar', None), ('example3:baz', 'sam')}
            }

        :return: Local level dependencies
        """
        return self._local_imports.copy()

    @property
    def module_dependencies(self) -> DependencyMapping:
        """
        Retrieve the module level dependencies.
        It is a mapping of strings of module names to tuples of where they come from.

        e.g. in module example.py::

            from example2 import foo as bar

            looks like:
            {
                'example2': ('example2.foo', 'bar')
            }

        :return: Module level dependencies
        """

        return self._surface_imports.copy()

    @property
    def deps(self) -> Tuple[DependencyMapping, DependencyMapping]:
        """
        Retrieve the imports found.

        :return: The module and local level imports
        """
        return self.module_dependencies, self.local_dependencies

    def reset_same_project(self):
        """
        Reset the import resolver to a state where it can be reused for the modules in the same project.
        """

        self._is_surface = True
        self._surface_imports.clear()
        self._local_imports.clear()
        self._function_name = ""

    def reset(self):
        """
        Reset the import resolver entirely.
        """

        self.reset_same_project()
        self._directory = None
        self._surface_values.clear()

    def visit_Module(self, node: ast.Module):
        """
        When a module is visited set the scope to surface level.

        :param node: The module node
        :return: The module node
        """

        super().generic_visit(node)
        self._is_surface = True
        return node

    def visit_Import(self, node: ast.Import):
        """
        Logic when an import node is visited.
        If the import is relative, the resolver attempts to resolve the package names
        and make the import absolute.

        :param node: The import node
        :return: The possibly altered import node
        """

        for alias_node in node.names:
            name = alias_node.name

            # absolute import path
            if "." in name:
                vals = alias_node.name.split(".")
                name = vals[len(vals) - 1]
            # does not have full path
            else:
                vals = self.key.split(".")
                vals[len(vals) - 1] = name
                filepath = Path(self._directory, os.sep.join(vals) + ".py")
                # if it exists in local directory it is a local file, not library
                if filepath.is_file():
                    alias_node.name = ".".join(vals)

            if self._is_surface:
                if alias_node.asname is None:
                    self._surface_imports[name] = (alias_node.name, name)
                else:
                    self._surface_imports[alias_node.asname] = (alias_node.name, alias_node.asname)
            else:
                if self._function_name not in self._local_imports:
                    self._local_imports[self._function_name] = set()

                if alias_node.asname is None:
                    self._local_imports[self._function_name].add((alias_node.name, None))
                else:
                    self._local_imports[self._function_name].add((alias_node.name, alias_node.asname))

        prev = self._is_surface
        self._is_surface = False
        super().generic_visit(node)
        self._is_surface = prev
        return node

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """
        Logic when an import from node is visited.
        If the import is relative, the resolver attempts to resolve the package names
        and make the import absolute.
        There is some more logic to consider because relative imports using from can be
        actual modules themselves.

        :param node: The import from node
        :return: The possibly altered import from node
        """

        # use the regex pattern to count the amount of continuous dots in the from statement
        imp_str = ast.unparse(node)
        match = COUNT_DOTS.match(imp_str)
        dot_count = 1
        if match:
            dot_count = len(match.group(2))

        module_name = node.module
        was_relative = False
        was_init = False
        if module_name is None:
            was_init = True
            was_relative = True
            node.module = "__init__"
            module_name = "__init__"

        # absolute path
        if "." not in module_name:
            vals = self.key.split(".")
            print(self.key)

            for i in range(dot_count):
                vals.pop()

            vals.append(node.module)
            filepath = Path(self._directory, os.sep.join(vals) + ".py")
            # if it exists in local directory it is a local file, not library
            if filepath.is_file():
                node.module = ".".join(vals)

        if node.names[0].name == "*" and "." in node.module:
            surface_level_vals = self._surface_values[node.module]
            lst = []
            for surface_level_val in surface_level_vals:
                lst.append(ast.alias(surface_level_val))
            node.names = lst

        for alias_node in node.names:
            if alias_node.name == "*":
                break

            if was_relative:

                vals = self.key.split(".")
                for i in range(dot_count):
                    vals.pop()

                vals.append(alias_node.name)
                filepath = Path(self._directory, os.sep.join(vals) + ".py")
                # if it exists in local directory it is a local file, not library

                if filepath.is_file():
                    alias_node.name = ".".join(vals)
                    was_relative = False

            if self._is_surface:
                if not hasattr(alias_node, "asname") or alias_node.asname is None:
                    if was_init and not was_relative:
                        node.module = node.module.replace("__init__", "*")

                    self._surface_imports[alias_node.name] = (node.module, None)
                else:
                    self._surface_imports[alias_node.asname] = (node.module, alias_node.name)
            else:
                if self._function_name not in self._local_imports:
                    self._local_imports[self._function_name] = set()

                if not hasattr(alias_node, "asname") or alias_node.asname is None:
                    if was_init and not was_relative:
                        node.module = node.module.replace("__init__", "*")

                    self._local_imports[self._function_name].add((node.module, alias_node.name))
                else:
                    self._local_imports[self._function_name].add((node.module, alias_node.asname))

        prev = self._is_surface
        self._is_surface = False
        super().generic_visit(node)
        self._is_surface = prev
        return node

    def visit(self, node: ast.AST):
        """
        Use this visit function to begin traversal.
        Throws exceptions if the current key or directory aren't set.

        :param node: The node to find
        :return:
        """

        if self._directory is None:
            raise ValueError("Can't visit without knowing project directory.")
        if self.key is None:
            raise ValueError("Can't visit without knowing the current module name.")

        return super().visit(node)

    def generic_visit(self, node: ast.AST) -> ast.AST:
        """
        Overwritten generic visit.

        :param node: Any other node visit not overwritten
        :return: The original node
        """

        prev = self._is_surface
        self._is_surface = False
        super().generic_visit(node)
        self._is_surface = prev
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        """
        Set the function scope to the current function.

        :param node: The function node
        :return: The function node (visited)
        """

        self._function_name = node.name
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        """
        Set the function scope to the current async function.

        :param node: The async function node
        :return: The async function node (visited)
        """

        self._function_name = node.name
        return self.generic_visit(node)
