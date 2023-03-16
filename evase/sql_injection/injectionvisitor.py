from typing import Any, Dict
import ast
from evase.sql_injection.injectionutil import get_all_vars
from evase.sql_injection.vulnerabletraversal import VulnerableTraversalChecker


class InjectionNodeVisitor(ast.NodeVisitor):
    sql_package_names = ["sqlite3", "mysql"]

    def __init__(self, project_struct, module_key):
        self.execute_funcs = {}
        self.vulnerable_funcs = {}
        self.current_func_node = None
        self.lst_of_assignments = []
        self.sql_marker = VulnerableTraversalChecker()
        self.if_flag = True
        self.project_struct = project_struct
        self.module_key = module_key

        # Dictionary used to store found execute statements before finding Cursor instantiation
        # Key is the name of the object calling the execute statement, and the value is the current function node
        self.sql_found_executes = {}

        # List to store found cursor instantiations before finding the corresponding execute statement
        self.sql_found_cursors = []

        # A list of function names that have already been determined to return a valid Cursor object
        self.sql_found_cursor_functions = []

        # Dictionary to handle link of function calls to save objects (because right now, the edge case checked is
        # whether the function returns a cursor object or not.
        # Key is the name of the function, value is the object name assigned to the return of this function
        self.function_calls = {}

        # This might have to be included for function calls
        self.second_pass = False

    def get_execute_funcs(self) -> Dict[Any, Any]:
        return self.execute_funcs

    def visit_Expr(self, node: ast.Expr):
        node_val = node.value
        if isinstance(node_val, ast.Call):
            node_func = node_val.func
            if isinstance(node_func, ast.Attribute):
                node_attr_name = node_func.value
                node_attr = node_func.attr
                if isinstance(node_attr_name, ast.Name):
                    node_object_name = node_attr_name.id
                    if node_attr == 'execute' and node_object_name in self.sql_found_cursors:
                        print('Found execute, continue on to bfs')
                        self.visit_execute(node_val)
                    elif node_attr == 'execute':
                        self.sql_found_executes[node_object_name] = self.current_func_node

        super().generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self.lst_of_assignments.append(node)

        if not self.second_pass:
            targs = node.targets
            node_val = node.value
            if isinstance(node_val, ast.Call) \
                    and isinstance(node_val.func, ast.Attribute) \
                    and isinstance(node_val.func.value, ast.Name):
                node_attr_val = node_val.func.value

                # Cursor() in 'cursor_obj = sql3.Cursor()'
                attr = node_val.func.attr

                # sql3 in 'cursor_obj = sql3.Cursor()'
                # or get_cursor() in 'cursor_obj = get_cursor()'
                object_name = node_attr_val.id

                if attr is not None and attr.lower() == 'cursor' and object_name in self.sql_package_names:
                    for targ in targs:
                        if isinstance(targ, ast.Name):
                            if targ.id in self.sql_found_executes.keys():
                                # Cursor found with associated execute
                                print("Found associated execute")
                                self.visit_execute(self.sql_found_executes[targ.id])
                            else:
                                self.sql_found_cursors.append(targ.id)
                elif attr is None and object_name in self.sql_found_cursor_functions:
                    for targ in targs:
                        if isinstance(targ, ast.Name):
                            targ_id = targ.id
                            if targ_id in self.sql_found_executes.keys():
                                print("Found associated execute")
                                self.visit_execute(self.sql_found_executes[targ_id])
                            else:
                                self.sql_found_cursors.append(targ.id)
                elif attr is None:
                    if isinstance(self.current_func_node, ast.FunctionDef):
                        first_targ = targs[0]
                        if isinstance(first_targ, ast.Name):
                            self.function_calls[object_name] = first_targ.id

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
        node_val = node.value
        if isinstance(node_val, ast.Call) \
                and isinstance(node_val.func, ast.Attribute) \
                and isinstance(node_val.func.value, ast.Name):
            node_attr = node_val.func.attr
            node_attr_name = node_val.func.value
            node_object_name = node_attr_name.id
            if node_attr.lower() == 'cursor' and node_object_name in self.sql_package_names:
                # Return call returns a valid sql Cursor object, therefore store function name if not stored
                function_name = self.current_func_node.name
                if function_name not in self.sql_found_cursor_functions:
                    self.sql_found_cursor_functions.append(function_name)

                # Not sure about this section
                for func_node in self.lst_of_assignments:
                    if isinstance(func_node, ast.Assign) \
                            and isinstance(func_node.value, ast.Call) \
                            and isinstance(func_node.value.func, ast.Name):
                        func_targs = func_node.targets
                        func_id = func_node.value.func.id
                        if func_id == function_name:
                            # Potentially remove function from list

                            # Function was checked previously in the AST, now we need the name of the object assigned
                            for targ in func_targs:
                                if isinstance(targ, ast.Name):
                                    if targ.id in self.sql_found_executes.keys():
                                        # Cursor found with associated execute
                                        print("Found associated execute")
                                        self.visit_execute(self.sql_found_executes[targ.id])
                                    else:
                                        self.sql_found_cursors.append(targ.id)

                            continue
        super().generic_visit(node)
        self.lst_of_assignments.append(node)

    def visit_Call(self, node: ast.Call):
        if hasattr(node.func, "attr") and node.func.attr == "execute":
            print(self.lst_of_assignments)
            self.visit_execute(node)
        super().generic_visit(node)

    def visit_execute(self, node: ast.Call):
        lst = self.lst_of_assignments.copy()

        print(self.lst_of_assignments)

        arg_list = get_all_vars(node.args[0])
        curr_scope = self.get_current_scope()
        print("EXEC found, curr scope:", curr_scope)
        print(self.current_func_node.parent_classes)

        result = self.sql_marker.traversal_from_exec(lst, self.current_func_node, arg_list, self.project_struct,
                                                     self.module_key)
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
        super().generic_visit(node)


def get_current_scope(self):
    if self.current_func_node:
        return self.current_func_node.name
    else:
        return ""


def get_vulnerable_funcs(self):
    return self.vulnerable_funcs


if __name__ == '__main__':
    anyone = InjectionNodeVisitor()
