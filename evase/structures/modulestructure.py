import ast
from evase.depanalyze.scoperesolver import ScopeResolver


class ModuleAnalysisStruct:

    def __init__(self, module_name: str, ast_tree: ast.AST, path: str):
        """
        A structure for the easier analysis of a single code module.
        Contains properties of the module such as scoping information.
        Initialize a module analysis structure with a tree.

        :param ast_tree: The ast of the module
        """
        self.module_name = module_name
        self.ast_tree = ast_tree
        self.path = path
        self.local_imports = {}
        self.module_imports = {}
        self.funcs = []

    def resolve_scopes(self, scr: ScopeResolver):
        self.ast_tree = scr.visit(self.ast_tree)

    def resolve_funcs(self):
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                self.funcs.append(node)

    def get_name(self):
        return self.module_name

    def get_ast(self) -> ast.AST:
        """
        Retrieve the internal ast tree.
    def get_ast(self) -> ast.AST:
        :return: ast for the module
        """
        return self.ast_tree

    def set_ast(self, ast):
        self.ast_tree = ast

    def get_funcs(self):
        return self.funcs

    def get_local_imports(self):
        return self.local_imports

    def set_local_imports(self, local_imports):
        self.local_imports = local_imports

    def get_module_imports(self):
        return self.module_imports

    def set_module_imports(self, module_imports):
        self.module_imports = module_imports

    def to_json(self):
        return {
            'pkg_name': self.module_name,
            'mdl_path': self.path
        }
