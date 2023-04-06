from typing import Any, Dict
import ast
from evase.sql_injection.injectionutil import get_all_vars
from evase.depanalyze.searching import FunctionCallFinder as UsesFinder
from evase.sql_injection.vulnerabletraversal import traversal_from_exec, make_vul_path_graph
from evase.util.logger import AnalysisLogger


class InjectionNodeVisitor(ast.NodeVisitor):
    # cursor_name = None
    # sql_package_names = ["sqlite3", "mysql"]
    def __init__(self, project_struct, module_key):
        """
        An AST traversal class that looks for instances of SQL injection patterns.

        :param project_struct: The project structure object
        :param module_key: The current module within the project
        """
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

    def visit_Expr(self, node: ast.Expr):
        """
        When visiting an expression node.

        :param node: The expression node
        """

        super().generic_visit(node)

    def visit_Assignment(self, node):
        """
        When visiting an assignment, collect the data.

        :param node: The assignment node
        """
        self._lst_of_assignments.append(node)
        super().generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """
        When visiting an assignment, collect the data.

        :param node: The assignment node
        """
        self.visit_Assignment(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """
        When visiting an assignment, collect the data.

        :param node: The assignment node
        """
        self.visit_Assignment(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        """
        When visiting an assignment, collect the data.

        :param node: The assignment node
        """
        self.visit_Assignment(node)

    def visit_If(self, node: ast.If):
        """
        Capture control flow nodes.

        :param node: The if node
        """

        if self._if_flag:
            self._lst_of_assignments.append("if")
        for val in node.body:
            self.visit(val)

        if len(node.orelse) > 0:
            prev = self._if_flag
            self._if_flag = False
            self.visit_Else(node.orelse)
            self._if_flag = prev

        if self._if_flag:
            self._lst_of_assignments.append("endif")

    def visit_Else(self, nodes):
        """
        Capture control flow nodes.

        :param nodes: Not an actual node, but the else part of an if node
        """
        if len(nodes) == 0:
            self._lst_of_assignments.append("endelse")
        else:
            self._lst_of_assignments.append("else")
            for node in nodes:
                self.visit(node)

    def visit_While(self, node: ast.While):
        """
        Capture control flow nodes.

        :param node: The while node
        """
        self._lst_of_assignments.append("while")
        super().generic_visit(node)
        self._lst_of_assignments.append("endwhile")

    def visit_For(self, node: ast.For):
        """
        Capture control flow nodes.

        :param node: The for node
        """
        self._lst_of_assignments.append("for")
        super().generic_visit(node)
        self._lst_of_assignments.append("endfor")

    def visit_Return(self, node: ast.Return):
        """
        Return nodes count as assignments.

        :param node: The retrurn node
        """
        super().generic_visit(node)
        self._lst_of_assignments.append(node)

    def visit_Call(self, node: ast.Call):
        """
        A call node could be a call to an execute statement.
        Further analysis done here.

        :param node: The call node
        """
        if hasattr(node.func, "attr") and node.func.attr == "execute":
            if self._current_func_node is None:
                AnalysisLogger().info(f"Execute statement found within {self._module_key}:*")
            else:
                AnalysisLogger().info(f"Execute statement found within {self._module_key}:{self._current_func_node}")

            self.visit_Execute(node)
        super().generic_visit(node)

    def visit_Execute(self, node: ast.Call):
        """
        When a call node is invoking a SQL execute statement, perform BFS.

        :param node: The call node
        """
        lst = self._lst_of_assignments.copy()

        arg_list = get_all_vars(node.args[0])
        curr_scope = self.current_scope

        self._uses_finder.reset_same_project()
        result = traversal_from_exec(self._uses_finder, lst, self._current_func_node, arg_list,
                                     self._module_key, start_from=node)

        if result is not None:
            module_full_name = f'{self._module_key}.{self._current_func_node.name}'
            self._vulnerable_funcs[module_full_name] = make_vul_path_graph(result)
        self._execute_funcs[curr_scope] = self._current_func_node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """
        When a function definition is met, restart assignment collection.

        :param node: The function node
        """
        self._current_func_node = node
        self._lst_of_assignments = []
        super().generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """
        When a function definition is met, restart assignment collection.

        :param node: The function node
        """
        self.visit_FunctionDef(node)

    @property
    def current_scope(self) -> str:
        """
        Get the current scope of the visitor.

        :return: Current functional scope
        """

        if self._current_func_node:
            return self._current_func_node.name
        else:
            return ""

    @property
    def vulnerable_funcs(self):
        """
        Get the current vulnerable functions.

        :return: Vulnerable functions collected
        """
        return self._vulnerable_funcs
