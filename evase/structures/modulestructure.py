import ast
from typing import List, Dict

from evase.depanalyze.surfacedetector import SurfaceLevelVisitor

from evase.depanalyze.scoperesolver import ScopeResolver


class ModuleAnalysisStruct:

    def __init__(self, module_name: str, ast_tree: ast.AST, path: str):
        """
        A structure for the easier analysis of a single code module.
        Contains properties of the module such as scoping information.
        Initialize a module analysis structure with a tree.

        :param ast_tree: The ast of the module
        """
        self.__module_name = module_name
        self.__ast_tree = ast_tree
        self.__path = path
        self.__local_imports = {}
        self.__module_imports = {}
        self.__funcs = []
        self.__scope_resolver = ScopeResolver()

        self.__surface_detector = SurfaceLevelVisitor()

        self.__resolve_scopes()
        self.__resolve_funcs()

    def __resolve_scopes(self):
        """
        Resolve the functional scopes in the ast tree.

        :param scr: The scope resolver object
        """

        self.__ast_tree = self.__scope_resolver.visit(self.__ast_tree)

    def __resolve_funcs(self):
        """
        Collect the names of function nodes in the project.
        """

        for node in ast.walk(self.__ast_tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                self.__funcs.append(node)

    def get_name(self) -> str:
        """
        Retrieve the name of the module being analyzed.

        :return: The module name as string
        """

        return self.__module_name

    def get_ast(self) -> ast.AST:
        """
        Retrieve the internal ast tree.

        :return: ast for the module
        """
        return self.__ast_tree

    def set_ast(self, ast_tree: ast.AST):
        """
        Set the internal AST tree.

        :param ast_tree: The syntax tree for the module
        """
        self.__ast_tree = ast_tree

    def get_funcs(self) -> List[ast.FunctionType]:
        """
        Get the resolved function nodes.

        :return: The list of function nodes
        """
        return self.__funcs

    def get_local_imports(self) -> Dict:
        """
        Get the given local imports.

        :return: The mapping of local imports
        """

        return self.__local_imports

    def set_local_imports(self, local_imports: Dict):
        """
        Set the local imports.

        :param local_imports: The mapping of local level imports
        """
        self.__local_imports = local_imports

    def get_module_imports(self) -> Dict:
        """
        Retrieve the module level imports.

        :return: The mapping of module level imports
        """
        return self.__module_imports

    def set_module_imports(self, module_imports: Dict):
        """
        Set the module level imports.

        :param module_imports: The module level import mapping
        """

        self.__module_imports = module_imports
