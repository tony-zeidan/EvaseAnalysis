import ast
from pathlib import Path
from typing import Dict, Union, TypedDict

from evase.depanalyze.importresolver import ModuleImportResolver

from evase.depanalyze.scoperesolver import ScopeResolver
from evase.depanalyze.surfacedetector import SurfaceLevelVisitor

from evase.structures.modulestructure import ModuleAnalysisStruct

from evase.util.logger import AnalysisLogger

from pprint import pprint

from evase.util.fileutil import get_project_module_names, check_path

ProjectStructure = TypedDict('ModuleStructure', {
    str: ModuleAnalysisStruct
})


def dir_to_module_structure(dirpath: Union[str, Path]) -> ProjectStructure:
    """
    Converts a directory into a mapping of package style names to module analysis structures

    :param dirpath: The path to the directory of the code
    :return: A mapping of module names to analysis structures
    """

    tree = {}
    dirpath = Path(dirpath).absolute()
    scr = ScopeResolver()
    mdr = ModuleImportResolver()
    slre = SurfaceLevelVisitor()

    for module_name, path in get_project_module_names(dirpath):
        AnalysisLogger().info(f"Module name {module_name} found.")
        path = Path(path).absolute()

        with open(path, 'r') as file:
            tree[module_name] = ModuleAnalysisStruct(
                module_name,
                ast.parse(file.read()),
                path,
                dirpath,
                scope_resolver_instance=scr,  # for efficiency, use the same scope resolver instance
                import_resolver_instance=mdr  # for efficiency, use the same import resolver instance
                surface_resolver_instance=slre, # for efficiency, use the same surface resolver instance
            )
            AnalysisLogger().info(f"Module name {module_name} created.")

    return tree


class ProjectAnalysisStruct:

    def __init__(self, prj_name: str, prj_root: Union[str, Path]):
        """
        A class that represents the structure of a Python project.
        The class analyzes the dependencies between files, and transforms this into a workable module structure.

        :param prj_name: The name of the project
        :param prj_root: The root directory of the project
        """
        self._prj_name = prj_name
        self._prj_root = check_path(prj_root, file_ok=False, absolute_req=False, ret_absolute=True)
        self._module_structure = dir_to_module_structure(self._prj_root)
        self._resolve_imports()

        # dependency graph
        self._depgraph = None
        AnalysisLogger().info("Making static dependency graph for project.")
        self._make_static_depgraph()
        

    @property
    def root(self) -> Path:
        """
        Retrieve the root given for the project.

        :return: The root of the project
        """
        return self._prj_root

    @property
    def structure(self) -> ProjectStructure:
        """
        Retrieve the structure of the project.
        It is a mapping between module names and their structures.

        :return: The structure mapping
        """
        return self._module_structure

    @property
    def dependency_mapping(self):
        """
        Retrieve a dependency graph of the project.
        It is a mapping between the names of a module/module function and
        a collection of the modules that it imports, etc.

        :return: The static dependency graph of the project
        """
        return self._depgraph

    def _resolve_imports(self):
        """
        Resolve the dependencies of each individual module structure in the project.
        Requires a traversal of the module 2 times.
        One traversal to collect surface level importable items for each module.
        One traversal to alter dependencies based on possible importable items.
        """

        surface_values = {mdl_name: mdl_struct.surface_items for mdl_name, mdl_struct in
                          self._module_structure.items()}

        AnalysisLogger().info("Resolving imports for the entire project.")
        for mdl_struct in self._module_structure.values():
            mdl_struct.resolve_imports(surface_values)

    def _make_static_depgraph(self):
        """
        Makes a static dependency graph for the project.
        """

        depgraph = {}
        for k, v in self._module_structure.items():

            depgraph[k] = {}

            for aname, (mdl_name, fn_name) in v.module_imports.items():

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

            for fn_name, names in v.local_imports.items():

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

        self._depgraph = depgraph

        # display dependency graph after generation
        #print("Static Dependency Graph")
        #pprint(depgraph)

    def __str__(self):
        """
        Make a string representation of the project structure
        :return:
        """

        return f'{self._prj_name}@{self._prj_root}'

    def __getitem__(self, key: str) -> ModuleAnalysisStruct:
        """
        Dictionary-like behavior, allow for accessing of modules through their names.

        :param key: The name of a module in the structure
        :return: The module structure for the module specified
        """
        return self._module_structure[key]
