from typing import Any, Dict
import ast
from evase.sql_injection.injectionutil import get_all_vars
from evase.sql_injection.vulnerabletraversal import VulnerableTraversalChecker


class InjectionNodeVisitor(ast.NodeVisitor):
    # cursor_name = None
    # sql_package_names = ["sqlite3", "mysql"]
    def __init__(self, project_struct, module_key):
        self.execute_funcs = {}
        self.vulnerable_funcs = {}
        self.current_func_node = None
        self.lst_of_assignments = []
        self.sql_marker = VulnerableTraversalChecker(project_struct)
        self.if_flag = True
        self.project_struct = project_struct
        self.module_key = module_key

    def get_execute_funcs(self) -> Dict[Any, Any]:
        return self.execute_funcs

    def visit_Expr(self, node: ast.Expr):
        super().generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self.lst_of_assignments.append(node)
        super().generic_visit(node)

    def visit_If(self, node: ast.If):
        if self.if_flag:
            self.lst_of_assignments.append("if")
        for val in node.body:
            self.visit(val)

        if len(node.orelse) > 0:
            prev = self.if_flag
            self.if_flag = False
            self.else_visit(node.orelse)
            self.if_flag = prev

        if self.if_flag:
            self.lst_of_assignments.append("endif")

    def else_visit(self, nodes):
        if len(nodes) == 0:
            self.lst_of_assignments.append("endelse")
        else:
            self.lst_of_assignments.append("else")
            for node in nodes:
                self.visit(node)

    def visit_While(self, node: ast.While) -> Any:
        self.lst_of_assignments.append("while")
        super().generic_visit(node)
        self.lst_of_assignments.append("endwhile")

    def visit_For(self, node: ast.For) -> Any:
        self.lst_of_assignments.append("for")
        super().generic_visit(node)
        self.lst_of_assignments.append("endfor")

    def visit_Return(self, node: ast.Return) -> Any:
        super().generic_visit(node)
        self.lst_of_assignments.append(node)

    def visit_Call(self, node: ast.Call):
        if hasattr(node.func, "attr") and node.func.attr == "execute":
            print(self.lst_of_assignments)
            self.visit_execute(node)
        super().generic_visit(node)

    def visit_execute(self, node: ast.Call):
        lst = self.lst_of_assignments.copy()

        arg_list = get_all_vars(node.args[0])
        curr_scope = self.get_current_scope()

        result = self.sql_marker.traversal_from_exec(lst, self.current_func_node, arg_list,
                                                     self.module_key, start_from=node)
        if result is not None:
            module_full_name = f'{self.module_key}.{self.current_func_node.name}'
            self.vulnerable_funcs[module_full_name] = result
        self.execute_funcs[curr_scope] = self.current_func_node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.current_func_node = node
        self.lst_of_assignments = []
        super().generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def get_current_scope(self):
        if self.current_func_node:
            return self.current_func_node.name
        else:
            return ""

    def get_vulnerable_funcs(self):
        return self.vulnerable_funcs


if __name__ == '__main__':
    anyone = InjectionNodeVisitor()
