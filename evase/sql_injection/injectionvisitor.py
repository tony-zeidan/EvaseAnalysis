from typing import Any, Dict
import ast
from evase.sql_injection.injectionutil import get_all_vars
from evase.depanalyze.searching import FunctionCallFinder as UsesFinder
from evase.sql_injection.vulnerabletraversal import traversal_from_exec, make_vul_path_graph


class InjectionNodeVisitor(ast.NodeVisitor):
    # cursor_name = None
    # sql_package_names = ["sqlite3", "mysql"]
    def __init__(self, project_struct, module_key):
        self._execute_funcs = {}
        self._vulnerable_funcs = {}

        # set the project structure and uses finder
        self._project_struct = project_struct
        self._uses_finder = UsesFinder()
        self._uses_finder.project_struct = project_struct

        self._current_func_node = None
        self._lst_of_assignments = []
        self._if_flag = True

        self._module_key = module_key

    def get_execute_funcs(self) -> Dict[Any, Any]:
        return self._execute_funcs

    def visit_Expr(self, node: ast.Expr):
        super().generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self._lst_of_assignments.append(node)
        super().generic_visit(node)

    def visit_If(self, node: ast.If):
        if self._if_flag:
            self._lst_of_assignments.append("if")
        for val in node.body:
            self.visit(val)

        if len(node.orelse) > 0:
            prev = self._if_flag
            self._if_flag = False
            self.else_visit(node.orelse)
            self._if_flag = prev

        if self._if_flag:
            self._lst_of_assignments.append("endif")

    def else_visit(self, nodes):
        if len(nodes) == 0:
            self._lst_of_assignments.append("endelse")
        else:
            self._lst_of_assignments.append("else")
            for node in nodes:
                self.visit(node)

    def visit_While(self, node: ast.While) -> Any:
        self._lst_of_assignments.append("while")
        super().generic_visit(node)
        self._lst_of_assignments.append("endwhile")

    def visit_For(self, node: ast.For) -> Any:
        self._lst_of_assignments.append("for")
        super().generic_visit(node)
        self._lst_of_assignments.append("endfor")

    def visit_Return(self, node: ast.Return) -> Any:
        super().generic_visit(node)
        self._lst_of_assignments.append(node)

    def visit_Call(self, node: ast.Call):
        if hasattr(node.func, "attr") and node.func.attr == "execute":
            print(self._lst_of_assignments)
            self.visit_execute(node)
        super().generic_visit(node)

    def visit_execute(self, node: ast.Call):
        lst = self._lst_of_assignments.copy()

        arg_list = get_all_vars(node.args[0])
        curr_scope = self.get_current_scope()

        self._uses_finder.reset_same_project()
        result = traversal_from_exec(self._uses_finder, lst, self._current_func_node, arg_list,
                                     self._module_key, start_from=node)

        if result is not None:
            module_full_name = f'{self._module_key}.{self._current_func_node.name}'
            self._vulnerable_funcs[module_full_name] = make_vul_path_graph(result)
        self._execute_funcs[curr_scope] = self._current_func_node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._current_func_node = node
        self._lst_of_assignments = []
        super().generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def get_current_scope(self):
        if self._current_func_node:
            return self._current_func_node.name
        else:
            return ""

    def get_vulnerable_funcs(self):
        return self._vulnerable_funcs


if __name__ == '__main__':
    anyone = InjectionNodeVisitor()
