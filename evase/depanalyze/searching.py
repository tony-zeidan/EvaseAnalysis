import ast
from typing import List
from enum import Enum
from evase.depanalyze.codetraversalnode import CodeTraversalNode
from evase.sql_injection.injectionutil import get_all_vars
from evase.structures.modulestructure import ModuleAnalysisStruct
from evase.structures.projectstructure import ProjectAnalysisStruct


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
        # print("Regular function call, not an object function call.")
        pass
    else:
        fn_name = caller_type + '.' + fn_name

    # using the dependencies of the current module, find the modules that is uses the function from (should be one).
    mdls = []
    for imp, (imp_mdl, imp_name) in mdl_struct.module_imports.items():
        if fn_name == imp_name:
            mdls.append(imp_mdl)

    # after finding the module(s) that this function comes from, visit them.
    fn_defs = []
    for mdl in mdls:
        mdl = prj_struct[mdl]
        for mdl_func in mdl.funcs:
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
    local_import = mdl_struct.local_imports
    module_import = mdl_struct.module_imports
    # case1, importing entire module
    if import_module in local_import.keys() or import_module in module_import.keys():
        return ImportUsesCase.ENTIRE_MODULE, import_module

    # case2, importing vulnerable function
    if import_func in local_import.keys() or import_func in module_import.keys():
        return ImportUsesCase.ONLY_FUNCTION, import_func

    # case3, importing vul function with AS
    for key, val in local_import.items():
        for class_name, original_func_name in val:
            # print("Checking 3" + class_name, original_func_name)
            if original_func_name == import_func:
                return ImportUsesCase.ONLY_FUNCTION_AS, key

    for key in module_import:
        func_as_name = key
        class_name, original_func_name = module_import[key]
        # print("[" + class_name, ',', original_func_name + "]")
        if original_func_name == import_func:
            return ImportUsesCase.ONLY_FUNCTION_AS, func_as_name

    # case4, importing entire module with AS
    for key, val in local_import.items():
        for class_name, class_as_name in val:
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
    def __init__(self, prj_struct: ProjectAnalysisStruct = None, module_name: str = None, func_name: str = None):
        """
        A class that finds the uses of a function in other modules.
        The class can be used to retrieve a list of nodes representing functions in other modules
        that the given function is used in.

        :param prj_struct: The structure of the project encapsulated in a ProjectAnalysisStruct
        :param module_name: The name of the module containing the function
        :param func_name: The name of the function
        """

        self._module_name = module_name
        self._curr_module = None
        self._module_target = None
        self._func_name = func_name
        self._func_target = None
        self._prj_struct = prj_struct
        self._current_func_node = None  # not important, just keep track
        self._current_func_scope = None
        self._found_calling_lst = []  # List for storing all the parent function of the vulnerable function

        self._assignments = []
        self.if_flag = True

    @property
    def project_struct(self) -> ProjectAnalysisStruct:
        """
        Get the project structure.

        :return: The project structure being used to obtain module data from
        """

        return self._prj_struct

    @project_struct.setter
    def project_struct(self, project_struct: ProjectAnalysisStruct):
        """
        Set the project structure.

        :param project_struct: The project structure to obtain module data from
        """

        self._prj_struct = project_struct

    @property
    def module_name(self) -> str:
        """
        Retrieve the name of the module containing the function to find uses for.

        :return: The name of the module that contains the function
        """
        return self._module_name

    @module_name.setter
    def module_name(self, module_name: str):
        """
        Set the name of the module that the function to find uses for is in.

        :param module_name: The name of the module that contains the function
        """

        if module_name is None or not isinstance(module_name, str):
            raise ValueError("An invalid module_name was passed.")

        self._module_name = module_name

    @property
    def func_name(self) -> str:
        """
        Get the function name the traverser is trying to find.

        :return: The name of the function to find
        """
        return self._func_name

    @func_name.setter
    def func_name(self, func_name: str):
        """
        Set the name of the function the traverser is trying to find.

        :param func_name: The name of the function to find
        """

        if func_name is None or not isinstance(func_name, str):
            raise ValueError("An invalid module_name was passed.")

        self._func_name = func_name

    @property
    def function_uses(self) -> List[CodeTraversalNode]:
        """
        Retrieve the function uses (after processing).

        :return: Function uses as code traversal nodes
        """
        return self._found_calling_lst

    def reset_same_project(self):
        """
        Reset the current instance so that it is still usable within the project.
        """
        self._module_name = None
        self._curr_module = None
        self._module_target = None
        self._func_name = None
        self._func_target = None
        self._current_func_node = None  # not important, just keep track
        self._current_func_scope = None
        self._found_calling_lst.clear()  # List for storing all the parent function of the vulnerable function
        self._assignments.clear()
        self.if_flag = True

    def reset(self):
        """
        Reset the current instance entirely.
        """

        self.reset_same_project()
        self._prj_struct = None

    def process(self):
        """
        Runs the function call finder on the current loaded project.
        """

        if self._module_name is None or self._func_name is None:
            raise ValueError("Can't check for uses of the function if either the function name or module name isn't "
                             "set.")

        if self._prj_struct is None:
            raise ValueError("Can't check for uses of the function if the project structure is not set.")

        for module_name, module_struct in self._prj_struct.structure.items():
            # self.module_name = module_name

            if module_name != self.module_name:
                case, asname = differentiate_imports(module_struct, self._func_name, self.module_name)
            else:
                case = ImportUsesCase.ONLY_FUNCTION

            self._curr_module = module_name
            self._func_target = self._func_name
            self._module_target = module_name

            if case == ImportUsesCase.NO_IMPORTS:
                continue

            elif case == ImportUsesCase.ONLY_FUNCTION:
                # print(f"CASE 2: vulnerable function found imported, next step look for function calls [{func_name}]")
                self._module_target = None
            elif case == ImportUsesCase.ONLY_FUNCTION_AS:
                # print(f"CASE 3: vulnerable function found imported using AS, next step look for function calls [{asname}]")
                self._module_target = None
                self._func_target = asname

            elif case == ImportUsesCase.ENTIRE_MODULE_AS:
                # print(f"CASE 4: vulnerable class found imported using AS, next step look for [{asname}.{func_name}]")
                self._module_target = asname

            self.visit(module_struct.tree)

    def visit_Call(self, node: ast.Call):
        """
        When visiting a function call node, this could perhaps be a use of the function we are trying to find.

        :param node: The function node
        """

        if not self._module_target:
            if isinstance(node.func, ast.Attribute):
                calling_function_name = node.func.attr
            else:
                calling_function_name = node.func.id

            if calling_function_name == self._func_target:
                injection_var = []
                for arg in node.args:
                    injection_var.append(get_all_vars(arg))
                self._found_calling_lst.append(
                    CodeTraversalNode(
                        self._curr_module,
                        func_node=self._current_func_node,
                        assignments=self._assignments.copy(),
                        variables=injection_var,
                        from_node=node))
        else:
            attrbute_node = node.func
            if hasattr(attrbute_node, "value") and hasattr(attrbute_node.value, "id"):
                calling_module_name = attrbute_node.value.id
                calling_function_name = attrbute_node.attr
                if calling_function_name == self._func_name and calling_module_name == self._module_target:
                    injection_var = []
                    for arg in node.args:
                        injection_var.append(get_all_vars(arg))

                    self._found_calling_lst.append(
                        CodeTraversalNode(
                            self._curr_module,
                            func_node=self._current_func_node,
                            assignments=self._assignments.copy(),
                            variables=injection_var,
                            from_node=node))

    def visit_Function(self, node: ast.FunctionType):
        """
        When visiting a function definition, set our current scope.

        :param node: The function node
        """
        self._current_func_scope = node.name
        self._current_func_node = node
        self._assignments = []
        super().generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """
        When visiting a function definition, set our current scope.

        :param node: The function node
        """

        self.visit_Function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """
        When visiting a function definition, set our current scope.

        :param node: The function node
        """
        self.visit_Function(node)

    def visit_Assignment(self, node):
        """
        When visiting an assignment, it could perhaps be inside a function and so for the BFS we collect these.

        :param node: The assignment node
        """
        super().generic_visit(node)
        self._assignments.append(node)

    def visit_Assign(self, node: ast.Assign):
        """
        When visiting an assignment, it could perhaps be inside a function and so for the BFS we collect these.

        :param node: The assignment node
        """
        self.visit_Assignment(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """
        When visiting an assignment, it could perhaps be inside a function and so for the BFS we collect these.

        :param node: The assignment node
        """
        self.visit_Assignment(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        """
        When visiting an assignment, it could perhaps be inside a function and so for the BFS we collect these.

        :param node: The assignment node
        """
        self.visit_Assignment(node)

    def visit_If(self, node: ast.If):
        """
        If we visit a conditional, track the current path.

        :param node: The node
        """

        if self.if_flag:
            self._assignments.append("if")
        for val in node.body:
            self.visit(val)

        if len(node.orelse) > 0:
            prev = self.if_flag
            self.if_flag = False
            self.visit_Else(node.orelse)
            self.if_flag = prev

        if self.if_flag:
            self._assignments.append("endif")

    def visit_Else(self, nodes):
        """
        If we visit a conditional, track the current path.

        :param nodes: The node
        """

        if len(nodes) == 0:
            self._assignments.append("endelse")
        else:
            self._assignments.append("else")
            for node in nodes:
                self.visit(node)

    def visit_While(self, node: ast.While):
        """
        If we visit a conditional, track the current path.

        :param node: The node
        """
        self._assignments.append("while")
        super().generic_visit(node)
        self._assignments.append("endwhile")

    def visit_For(self, node: ast.For):
        """
        If we visit a conditional, track the current path.

        :param node: The node
        """
        self._assignments.append("for")
        super().generic_visit(node)
        self._assignments.append("endfor")

    def visit_Return(self, node: ast.Return):
        """
        If we visit a conditional, track the current path.

        :param node: The node
        """
        self.visit_Assignment(node)

