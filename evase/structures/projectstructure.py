import ast
from pathlib import Path
from typing import Dict, Union

from evase.structures.modulestructure import ModuleAnalysisStruct

from pprint import pprint

from evase.util.fileutil import get_project_module_names, check_path


def dir_to_module_structure(dirpath: Union[str, Path]) -> Dict[str, ModuleAnalysisStruct]:
    """
    Converts a directory into a mapping of package style names to module analysis structures

    :param dirpath: The path to the directory of the code
    :return: A mapping of module names to analysis structures
    """

    tree = {}
    dirpath = Path(dirpath).absolute()

    for module_name, path in get_project_module_names(dirpath):

        path = Path(path).absolute()

        with open(path, 'r') as file:
            tree[module_name] = ModuleAnalysisStruct(module_name, ast.parse(file.read()), path, dirpath)

    return tree


class ProjectAnalysisStruct:

    def __init__(self, prj_name: str, prj_root: Union[str, Path]):
        """
        A class that represents the structure of a Python project.
        The class analyzes the dependencies between files, and transforms this into a workable module structure.

        :param prj_name: The name of the project
        :param prj_root: The root directory of the project
        """
        self.prj_name = prj_name
        self.__prj_root = check_path(prj_root, file_ok=False, absolute_req=False, ret_absolute=True)
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

                if "*" in mdl_name:
                    if aname not in mdl_name:
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

                    if "*" in mdl_name:
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

        # display dependency graph after generation
        print("Static Dependency Graph")
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

    def __getitem__(self, key: str) -> ModuleAnalysisStruct:
        """
        Dictionary-like behavior, allow for accessing of modules through their names.

        :param key: The name of a module in the structure
        :return: The module structure for the module specified
        """
        return self.__module_structure[key]
