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
        self._module_name = module_name
        self._ast_tree = ast_tree

        self._path = check_path(within_root_path, file_ok=True, file_req=True, absolute_req=False, ret_absolute=True)
        self._root = check_path(root_path, file_ok=False, file_req=False, absolute_req=False, ret_absolute=True)

        self._local_imports = {}
        self._module_imports = {}
        self._funcs = []
        self._surface_items = []

        if import_resolver_instance is None:
            import_resolver_instance = ModuleImportResolver()
        self._import_resolver_instance = import_resolver_instance
        self._import_resolver_instance.directory = self._root

        if scope_resolver_instance is None:
            scope_resolver_instance = ScopeResolver()

        self._scope_resolver_instance = scope_resolver_instance
        self._resolve()

    def _resolve(self):
        """
        Resolve the scopes of the functions inside the AST tree,
        and all the surface-level importable items from this module.
        """
        self._scope_resolver_instance.reset()
        self._scope_resolver_instance.module_name = self._module_name

        self._ast_tree = self._scope_resolver_instance.visit(self._ast_tree)
        # for efficiency resolver now contains the functions it visited (less traversals)
        self._funcs = self._scope_resolver_instance.funcs

        visitor = SurfaceLevelVisitor()
        visitor.visit(self._ast_tree)
        self._surface_items = visitor.surface_names

    def resolve_imports(self, surface_entities: Dict[str, List[str]]):
        """
        Resolve the modules imports at both module and local levels.

        :param surface_entities: The mapping of all surface entities for each module
        """

        transformer = self._import_resolver_instance
        transformer.reset_same_project()
        transformer.surface_values = surface_entities
        transformer.key = self._module_name
        modified_ast = transformer.visit(self._ast_tree)
        self._ast_tree = modified_ast

        self._module_imports, self._local_imports = transformer.deps

    @property
    def name(self) -> str:
        """
        Retrieve the name of the module being analyzed.

        :return: The module name as string
        """

        return self._module_name

    @property
    def tree(self) -> ast.AST:
        """
        Retrieve the internal ast tree.

        :return: ast for the module
        """

        return self._ast_tree

    @property
    def funcs(self) -> List[ast.FunctionType]:
        """
        Get the resolved function nodes.

        :return: The list of function nodes
        """
        return self._funcs.copy()

    @property
    def local_imports(self) -> DependencyMapping:
        """
        Get the resolved local imports.

        :return: The mapping of local imports
        """

        return self._local_imports.copy()

    @property
    def module_imports(self) -> DependencyMapping:
        """
        Get the resolved module imports

        :return: The mapping of module imports
        """
        return self._module_imports.copy()

    @property
    def surface_items(self) -> List[str]:
        """
        Get a list of the surface importable items for this module.

        :return: The surface items
        """

        return self._surface_items.copy()
