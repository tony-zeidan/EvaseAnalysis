import ast

from evase.structures.modulestructure import ModuleAnalysisStruct
from evase.structures.projectstructure import ProjectAnalysisStruct
from evase.typing.AssignmentCall import AssignmentCall


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


def get_all_targets(node: ast.Assign) -> list:
    """
    Gets all the targets for an assignment.

    :param node: The assignment node
    :return: The list of assignment ids
    """
    target_lst = []

    for target in node.targets:
        if isinstance(target, ast.Name):
            target_lst.append(target.id)

        elif hasattr(target, "elts"):
            for val in target.elts:
                if hasattr(val, "id"):
                    target_lst.append(val.id)

    return target_lst


def get_all_vars_types(node: ast.AST) -> set:
    """
    Recursively looks at a node and collects the variables used in that node (EXCLUDING THE BODY).

    :param node: The node to look through
    :return: The set of variable ids used inside a node
    """

    args = set()

    if isinstance(node, ast.Dict) or isinstance(node, ast.Set) or isinstance(node, ast.List):
        args.add(None)

    elif hasattr(node, "id"):
        args.add(AssignmentCall(None, str(node.id)))

    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            # self.call(), call(), a.call()
            if hasattr(node.func.value, "id"):
                args.add(AssignmentCall(str(node.func.attr), str(node.func.value.id)))
            else:
                args.add(AssignmentCall(str(node.func.attr)))

    elif hasattr(node, "elts"):
        for subarg in node.elts:
            for subsubarg in get_all_vars_types(subarg):
                args.add(subsubarg)

    elif isinstance(node, ast.BinOp):
        for l_subarg in get_all_vars_types(node.left):
            args.add(l_subarg)
        for r_subarg in get_all_vars_types(node.right):
            args.add(r_subarg)

    elif isinstance(node, ast.JoinedStr) or isinstance(node, ast.FormattedValue):
        args.add(type(""))

    elif isinstance(node, ast.Constant):
        args.add(type(node.value))

    elif hasattr(node, "value"):
        for subarg in get_all_vars_types(node.value):
            args.add(subarg)

    return args


def get_all_target_values_types(node: ast.Assign) -> list:
    """
    Gets the variables used in the assignment of each target.

    :param node: The assignment node
    :return: The list of values for each target, empty set signifies no variables
    """
    val_lst = [get_all_vars_types(node.value)]  # collect all variables mentioned for each assignment
    if len(val_lst) == 0:
        val_lst.append(set())

    return val_lst


def get_inner_scope_assignments(index, assignments):
    stack = ["end" + assignments[index]]
    index += 1
    inner_assignments = [[]]
    assignment_ind = 0

    while len(stack) != 0 and index < len(assignments):

        node = assignments[index]
        if node == "if" or node == "while" or node == "for":
            stack.append("end" + node)
        elif len(stack) == 1 and node == "else":
            inner_assignments.append([])
            assignment_ind += 1
            index += 1
            continue
        elif node == "endif" or node == "endwhile" or node == "endfor":
            removed = stack.pop()
            if removed != node: print("not same val" + removed + " " + node)
            if len(stack) == 0:
                index += 1
                break

        inner_assignments[assignment_ind].append(node)
        index += 1

    return index - 1, inner_assignments


def collect_vars_types(project_struct: ProjectAnalysisStruct, module_struct: ModuleAnalysisStruct, assignments, possible_variable_types, line_map):
    # get parameter types from func before
    # possible_variable_types = [{}] [{a:obj1}{a:obj2}]
    # module, object
    index = 0
    while index < len(assignments):
        node = assignments[index]
        if isinstance(node, ast.Call):
            line_map[node.lineno] = copy_list_map_set(possible_variable_types)

        elif isinstance(node, ast.Assign):
            line_map[node.lineno] = copy_list_map_set(possible_variable_types)

            # variables being assigned a value
            target_lst = get_all_targets(node)
            # values of variables being assigned
            target_type_lst = get_all_target_values_types(node)

            for i in range(len(target_lst)):  # for each variable being assigned
                target_variable = target_lst[i]
                if len(target_type_lst[i]) < 0:
                    for j in range(len(possible_variable_types)):
                        # update target variable type to none as no type is found (collection)
                        possible_variable_types[j][target_variable] = None
                else:
                    target_type = next(iter(target_type_lst[i]))
                    # id -> prev used, surface or import
                    # call() -> surface or import
                    # id.call() -> prev used, surface, or import, self is exception
                    get_function_call_origin(node, module_struct, project_struct, call)
                    print("")

                    # update target variable type
                    for j in range(len(possible_variable_types)):
                        # get function or variable (module, val)
                        # if function get return type
                        # if variable use look up and make equal to same type
                        # target_type = resolve(target_type_lst[i], moduleStruct)
                        possible_variable_types[j][target_variable] = target_type

        elif isinstance(node, ast.Return):
            break

        elif node == "if" or node == "while" or node == "for":
            index, inner_scope_assignments = get_inner_scope_assignments(index, assignments)

            # if elseif else
            for inner_scope_assignment in inner_scope_assignments:
                copy_var_type_lst = copy_list_map_set(possible_variable_types)
                # determine marked_lst in inner function, new_vulnerable is for when function returns are being analyzed
                collect_vars_types(moduleStruct, inner_scope_assignment, copy_var_type_lst, line_map)
                possible_variable_types.extend(copy_var_type_lst)
        index += 1


def copy_list_map_set(list_map_set):
    copy = []
    for map_set in list_map_set:
        copy.append(map_set.copy())
    return copy
