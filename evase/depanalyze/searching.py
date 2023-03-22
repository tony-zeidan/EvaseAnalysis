import ast
from typing import List
from enum import Enum
from evase.depanalyze.node import Node
from evase.sql_injection.injectionutil import get_all_vars
from evase.structures.modulestructure import ModuleAnalysisStruct
from evase.structures.projectstructure import ProjectAnalysisStruct, resolve_project_imports, dir_to_module_structure


class ImportUsesCase(Enum):
    NO_IMPORTS = 0
    ENTIRE_MODULE = 1
    ONLY_FUNCTION = 2
    ONLY_FUNCTION_AS = 3
    ENTIRE_MODULE_AS = 4


def get_function_call_origin(func_node: ast.Call, mdl_struct: ModuleAnalysisStruct, prj_struct: ProjectAnalysisStruct,
                             caller_type: str = None):
    """
    Find the function node for of a function that was invoked in code.
    Find where the function being called originated from.

    :param func_node: The function call node in the current module
    :param mdl_struct: The module structure that this function call was made in
    :param prj_struct: The project structure containing the dependency graph (other modules mapping)
    :param caller_type: The invokee of the function call (an object)
    :return: The function definition(s) for the function that was called
    """
    fn_name = func_node.func.id

    if caller_type is None:
        print("Regular function call, not an object function call.")
    else:
        fn_name = caller_type + '.' + fn_name

    # using the dependencies of the current module, find the modules that is uses the function from (should be one).
    mdls = []
    for imp, (imp_mdl, imp_name) in mdl_struct.get_module_imports().items():
        if fn_name == imp_name:
            mdls.append(imp_mdl)

    # after finding the module(s) that this function comes from, visit them.
    fn_defs = []
    for mdl in mdls:
        mdl = prj_struct.get_module(mdl)
        for mdl_func in mdl.get_funcs():
            if mdl_func.name == fn_name:
                fn_defs.append(mdl_func)

    return fn_defs


def differentiate_imports(mdl_struct: ModuleAnalysisStruct, import_func: str, import_module: str):
    """
    Differentiates the style of import that the function or module is being imported with.

    :param mdl_struct: The module structure that we are looking at
    :param import_func: The vulnerable function name as a String, we want to know in what way this function is imported, or not at all.
    :param import_module: The vulnerable module name as a String, we want to know in what way this module is imported, or not at all
    :return: The case that the import style falls under and the imported entity
    """

    # function can tell us if the vulnerale is imported as function or module
    local_import = mdl_struct.get_local_imports()
    module_import = mdl_struct.get_module_imports()
    # case1, importing entire module
    if import_module in local_import.keys() or import_module in module_import.keys():
        return ImportUsesCase.ENTIRE_MODULE, import_module

    # case2, importing vulnerable function
    if import_func in local_import.keys() or import_func in module_import.keys():
        return ImportUsesCase.ONLY_FUNCTION, import_func

    # case3, importing vul function with AS
    for key in local_import:
        func_as_name = key
        class_name, original_func_name = local_import[key]
        # print("Checking 3" + class_name, original_func_name)
        if original_func_name == import_func:
            return ImportUsesCase.ONLY_FUNCTION_AS, func_as_name

    for key in module_import:
        func_as_name = key
        class_name, original_func_name = module_import[key]
        # print("[" + class_name, ',', original_func_name + "]")
        if original_func_name == import_func:
            return ImportUsesCase.ONLY_FUNCTION_AS, func_as_name

    # case4, importing entire module with AS
    for key in local_import:
        class_name, class_as_name = local_import[key]
        # print("Checking 4" + class_name, class_as_name)

        if class_name == import_module:
            return ImportUsesCase.ENTIRE_MODULE_AS, class_as_name

    for key in module_import:
        class_name, class_as_name = module_import[key]
        # print("Checking 4" + class_name, class_as_name)
        if class_name == import_module:
            return ImportUsesCase.ENTIRE_MODULE_AS, class_as_name

    # not found related import, this file is not related for this vul
    return ImportUsesCase.NO_IMPORTS, None


class FunctionCallFinder(ast.NodeVisitor):
    def __init__(self, prj_struct: ProjectAnalysisStruct, func_mdl_name: str, func_name: str):
        """
        A class that finds the uses of a function in other modules.
        The class can be used to retrieve a list of nodes representing functions in other modules
        that the given function is used in.

        :param prj_struct: The structure of the project encapsulated in a ProjectAnalysisStruct
        :param func_mdl_name: The name of the module containing the function
        :param func_name: The name of the function
        """

        self.module_name = func_mdl_name
        self.module_target = None
        self.func_name = func_name
        self.func_target = None
        self.prj_struct = prj_struct
        self.current_func_node = None  # not important, just keep track
        self.current_func_scope = None
        self.found_calling_lst = []  # List for storing all the parent function of the vulnerable function

        self.lst_of_assignments = []
        self.if_flag = True

    def process(self):
        """
        Runs the function call finder on the current loaded project.
        """

        for module_name, module_struct in self.prj_struct.get_module_structure().items():
            if module_name != self.module_name:
                case, asname = differentiate_imports(module_struct, self.func_name, self.module_name)

                self.func_target = self.func_name
                self.module_target = self.module_name
                if case == 0:
                    continue

                elif case == 2:
                    # print(f"CASE 2: vulnerable function found imported, next step look for function calls [{func_name}]")
                    self.module_target = None
                elif case == 3:
                    # print(f"CASE 3: vulnerable function found imported using AS, next step look for function calls [{asname}]")
                    self.module_target = None
                    self.func_target = asname

                elif case == 4:
                    # print(f"CASE 4: vulnerable class found imported using AS, next step look for [{asname}.{func_name}]")
                    self.module_target = asname

            self.visit(module_struct.get_ast())

    def visit_Call(self, node: ast.Call):
        if self.module_target is None:
            if isinstance(node.func, ast.Attribute):
                calling_function_name = node.func.attr
            else:
                calling_function_name = node.func.id

            if calling_function_name == self.func_name:
                injection_var = []
                for arg in node.args:
                    injection_var.extend(list(get_all_vars(arg)))
                self.found_calling_lst.append(
                    Node(
                        self.module_name,
                        func_node=self.current_func_node,
                        assignments=self.lst_of_assignments.copy(),
                        injection_vars=injection_var,
                        from_node=node))
        else:
            attrbute_node = node.func
            if hasattr(attrbute_node, "value") and hasattr(attrbute_node, "value"):
                calling_module_name = attrbute_node.value.id
                calling_function_name = attrbute_node.attr
                if calling_function_name == self.func_name and calling_module_name == self.module_target:
                    injection_var = []
                    for arg in node.args:
                        injection_var.extend(list(get_all_vars(arg)))
                    self.found_calling_lst.append(
                        Node(
                            self.module_name,
                            func_node=self.current_func_node,
                            assignments=self.lst_of_assignments.copy(),
                            injection_vars=injection_var,
                            from_node=node))

    def visit_FunctionDef(self, node: ast.Expr):
        self.current_func_scope = node.name
        self.current_func_node = node
        self.lst_of_assignments = []
        super().generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        super().generic_visit(node)
        self.lst_of_assignments.append(node)

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

    def visit_While(self, node: ast.While):
        self.lst_of_assignments.append("while")
        super().generic_visit(node)
        self.lst_of_assignments.append("endwhile")

    def visit_For(self, node: ast.For):
        self.lst_of_assignments.append("for")
        super().generic_visit(node)
        self.lst_of_assignments.append("endfor")

    def visit_Return(self, node: ast.Return):
        super().generic_visit(node)
        self.lst_of_assignments.append(node)

    def get_uses(self) -> List[Node]:
        return self.found_calling_lst

    @staticmethod
    def find_function_uses(prj_struct: ProjectAnalysisStruct, function_module_name: str, function_name: str) -> List[
        Node]:
        """
        Find the uses for a function in other modules.
        Instantiates a FunctionCallFinder on the project, runs it on the project, and retrieves the uses.

        :param prj_struct: The project structure to look within
        :param function_module_name: The name of the defining module of the function to look for uses of
        :param function_name: The function to look for uses of
        :return: A list of nodes representing usages in other modules
        """
        finder = FunctionCallFinder(prj_struct, function_module_name, function_name)
        finder.process()
        return finder.get_uses()
