import ast
import os
from _ast import Module, ImportFrom, ClassDef, FunctionDef
from pathlib import Path


class ModuleImportResolver(ast.NodeTransformer):
    def __init__(self, surface_values, directory, logger=None):
        self._directory = directory
        self._is_surface = True
        self._surface_imports = {}
        self._local_imports = {}
        self._surface_values = surface_values
        self._function_name = ""
        self.logger = logger

    def get_dependencies(self):
        return self._surface_imports, self._local_imports

    def set_key(self, key):
        self.key = key

    def visit_Module(self, node: Module):
        super().generic_visit(node)
        self._is_surface = True
        return node

    def visit_Import(self, node: Module):

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
                filepath = Path(self._directory + os.sep + os.sep.join(vals) + ".py")
                # if it exists in local directory it is a local file, not library
                if filepath.is_file():
                    alias_node.name = ".".join(vals)

            print("SURFACE:", self._is_surface)
            print("name:", name)
            print("aliasname:", alias_node.name)
            print("alias as:", alias_node.asname)
            if self._is_surface:
                if alias_node.asname is None:
                    self._surface_imports[name] = [alias_node.name, name]
                else:
                    print("ASNAME:", alias_node.asname, alias_node)
                    self._surface_imports[alias_node.asname] = [alias_node.name, alias_node.asname]
            else:
                if alias_node.asname is None:
                    self._local_imports[self._function_name] = [alias_node.name, self._function_name]
                else:
                    self._local_imports[self._function_name] = [alias_node.name, alias_node.asname]

        prev = self._is_surface
        self._is_surface = False
        super().generic_visit(node)
        self._is_surface = prev
        return node

    def visit_ImportFrom(self, node: ImportFrom):
        module_name = node.module
        # absolute path
        if "." not in module_name:
            vals = self.key.split(".")
            vals[len(vals) - 1] = node.module
            filepath = Path(self._directory + os.sep + os.sep.join(vals) + ".py")
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
            if self._is_surface:
                if not hasattr(alias_node, "asname") or alias_node.asname is None:
                    self._surface_imports[alias_node.name] = [node.module, None]
                else:
                    self._surface_imports[alias_node.asname] = [node.module, alias_node.name]
            else:
                if not hasattr(alias_node, "asname") or alias_node.asname is None:
                    self._local_imports[self._function_name] = [node.module, alias_node.name]
                else:
                    self._local_imports[self._function_name] = [node.module, alias_node.asname]

        prev = self._is_surface
        self._is_surface = False
        super().generic_visit(node)
        self._is_surface = prev
        return node

    def generic_visit(self, node):
        prev = self._is_surface
        self._is_surface = False
        super().generic_visit(node)
        self._is_surface = prev
        return node

    def visit_FunctionDef(self, node: FunctionDef):
        self._function_name = node.name
        return self.generic_visit(node)
