import ast
from pathlib import Path
from typing import List, Dict, Union, Optional

from evase.depanalyze.importresolver import ModuleImportResolver, DependencyMapping

from evase.depanalyze.surfacedetector import SurfaceLevelVisitor

from evase.depanalyze.scoperesolver import ScopeResolver
from evase.util.fileutil import check_path


class ModuleAnalysisStruct:

    def __init__(
            self,
            module_name: str,
            ast_tree: ast.AST,
            within_root_path: Union[str, Path],
            root_path: Union[str, Path],
            import_resolver_instance: ModuleImportResolver = None,
            scope_resolver_instance: ScopeResolver = None
    ):
        """
        A structure for the easier analysis of a single code module.
        Contains properties of the module such as scoping information.
        Initialize a module analysis structure with a tree.

        :param ast_tree: The ast of the module
        """
        self.__module_name = module_name
        self.__ast_tree = ast_tree

        self.__path = check_path(within_root_path, file_ok=True, file_req=True, absolute_req=False, ret_absolute=True)
        self.__root = check_path(root_path, file_ok=False, file_req=False, absolute_req=False, ret_absolute=True)

        self.__local_imports = {}
        self.__module_imports = {}
        self.__funcs = []
        self.__surface_items = []

        if import_resolver_instance is None:
            import_resolver_instance = ModuleImportResolver()
        self.__import_resolver_instance = import_resolver_instance
        self.__import_resolver_instance.directory = self.__root

        if scope_resolver_instance is None:
            scope_resolver_instance = ScopeResolver()
        self.__scope_resolver_instance = scope_resolver_instance

        self.__resolve()

    def __resolve(self):
        """
        Resolve the scopes of the functions inside the AST tree,
        and all the surface-level importable items from this module.
        """
        self.__scope_resolver_instance.visit(self.__ast_tree)
        self.__ast_tree = self.__scope_resolver_instance.visit(self.__ast_tree)
        # for efficiency resolver now contains the functions it visited (less traversals)
        self.__funcs = self.__scope_resolver_instance.funcs

        visitor = SurfaceLevelVisitor()
        visitor.visit(self.__ast_tree)
        self.__surface_items = visitor.get_surface_names()

    def resolve_imports(self, surface_entities: Dict[str, List[str]]):
        """
        Resolve the modules imports at both module and local levels.

        :param path:
        :param surface_entities: The mapping of all surface entities for each module
        """

        transformer = self.__import_resolver_instance
        transformer.reset_same_project()
        transformer.surface_values = surface_entities
        transformer.key = self.__module_name
        modified_ast = transformer.visit(self.__ast_tree)
        self.__ast_tree = modified_ast

        self.__module_imports, self.__local_imports = transformer.deps

    @property
    def name(self) -> str:
        """
        Retrieve the name of the module being analyzed.

        :return: The module name as string
        """

        return self.__module_name

    @property
    def tree(self) -> ast.AST:
        """
        Retrieve the internal ast tree.

        :return: ast for the module
        """

        return self.__ast_tree

    @property
    def funcs(self) -> List[ast.FunctionType]:
        """
        Get the resolved function nodes.

        :return: The list of function nodes
        """
        return self.__funcs.copy()

    @property
    def local_imports(self) -> DependencyMapping:
        """
        Get the resolved local imports.

        :return: The mapping of local imports
        """

        return self.__local_imports.copy()

    @property
    def module_imports(self) -> DependencyMapping:
        """
        Get the resolved module imports

        :return: The mapping of module imports
        """
        return self.__module_imports.copy()

    @property
    def surface_items(self) -> List[str]:
        """
        Get a list of the surface importable items for this module.

        :return: The surface items
        """

        return self.__surface_items.copy()
