import ast
import os
from pathlib import Path
from typing import Dict

from evase.structures.modulestructure import ModuleAnalysisStruct

from pprint import pprint


def dir_to_module_structure(dirpath: str) -> Dict[str, ModuleAnalysisStruct]:
    """
    Converts a directory into a mapping of package style names to module analysis structures

    :param dirpath: The path to the directory of the code
    :return: A mapping of module names to analysis structures
    """

    tree = {}
    dirpath = Path(dirpath)

    keep_last = any(p.name == "__init__.py" for p in Path.iterdir(dirpath))

    files = dirpath.glob('**/*.py')
    for file in files:
        if keep_last:
            module_style = Path(os.path.splitext(file.relative_to(dirpath.parent))[0])
        else:
            module_style = Path(os.path.splitext(file.relative_to(dirpath))[0])
        module_style = str(module_style).replace(os.sep, '.')

        with open(file, 'r') as openfile:
            path = os.path.abspath(file)
            tree[module_style] = ModuleAnalysisStruct(module_style, ast.parse(openfile.read()), path)

    return tree


class ProjectAnalysisStruct:

    def __init__(self, prj_name: str, prj_root: str):
        """
        A class that represents the structure of a Python project.
        The class analyzes the dependencies between files, and transforms this into a workable module structure.

        :param prj_name: The name of the project
        :param prj_root: The root directory of the project
        """
        self.prj_name = prj_name

        if not os.path.exists(prj_root):
            raise ValueError("Can't accept a file path that doesn't exist.")

        self.__prj_root = prj_root
        self.__module_structure = dir_to_module_structure(self.__prj_root)
        self.__resolve_imports()

        # dependency graph
        self.__depgraph = None
        self.__make_static_depgraph()

    def __resolve_imports(self):
        """
        Resolve the dependencies of each individual module structure in the project.
        Requires a traversal of the module 2 times.
        One traversal to collect surface level importable items for each module.
        One traversal to alter dependencies based on possible importable items.
        """

        surface_values = {mdl_name: mdl_struct.get_surface_items() for mdl_name, mdl_struct in
                          self.__module_structure.items()}

        for mdl_struct in self.__module_structure.values():
            mdl_struct.resolve_imports(surface_values, self.__prj_root)

    def get_prj_root(self):
        """
        Retrieve the root given for the project.

        :return: The root of the project
        """
        return self.__prj_root

    def get_module_structure(self) -> Dict[str, ModuleAnalysisStruct]:
        """
        Retrieve the structure of the modules (use after processing)

        :return: Mapping of module names to analysis structures
        """
        return self.__module_structure

    def get_module(self, module_key) -> ModuleAnalysisStruct:
        """
        Retrieve the structure of the module

        :return: module analysis structures
        """
        return self.__module_structure.get(module_key)

    def __make_static_depgraph(self):
        """
        Makes a static dependency graph for the project.
        """

        depgraph = {}
        for k, v in self.__module_structure.items():

            depgraph[k] = {}

            for aname, (mdl_name, fn_name) in v.get_module_imports().items():

                print(f"\nSURFACE LEVEL\naname:{aname}\nmdl_name:{mdl_name}\nfn_name:{fn_name}")

                if mdl_name == "__init__":
                    # handle this case differently
                    if fn_name is None and aname not in depgraph[k]:
                        depgraph[k][aname] = []
                else:
                    if mdl_name not in depgraph[k]:
                        depgraph[k][mdl_name] = []

                    if fn_name == aname:
                        continue

                    elif fn_name is None:
                        depgraph[k][mdl_name].append(aname)

                    else:
                        if fn_name not in depgraph[k][mdl_name]:
                            depgraph[k][mdl_name].append(fn_name)

            for fn_name, names in v.get_local_imports().items():

                namer = f'{k}:{fn_name}'
                if namer not in depgraph:
                    depgraph[namer] = {}

                for mdl_name, aname in names:

                    print(f"\nLOCAL LEVEL\nkey:{k}\naname:{aname}\nmdl_name:{mdl_name}\nfn_name:{fn_name}\nnamer:{namer}")

                    if mdl_name == "__init__":
                        if aname not in depgraph[namer]:
                            depgraph[namer][aname] = []
                    else:
                        if fn_name == aname:
                            continue

                        else:
                            if mdl_name not in depgraph[namer]:
                                depgraph[namer][mdl_name] = []

                        depgraph[namer][mdl_name].append(aname)

        self.__depgraph = depgraph
        pprint(depgraph)

    def get_static_depgraph(self) -> Dict:
        """
        Retrieve the static dependency graph from the analysis structure.

        :return: The static dependency graph in dictionary form
        """
        return self.__depgraph

    def __str__(self):
        """
        Make a string representation of the project structure
        :return:
        """

        return f'{self.prj_name}@{self.__prj_root}'
