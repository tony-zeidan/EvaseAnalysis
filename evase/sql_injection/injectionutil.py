import ast


def get_function_params(node) -> list:
    """
    Finds the set of function parameters from an ast node.

    :param node: An ast node representing a function definition
    :return: The set of the function parameters
    """
    params = []
    args = node.args.args
    for arg in args:
        params.append(arg.arg)
    return params


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


def get_all_vars(node: ast.AST) -> set:
    """
    Recursively looks at a node and collects the variables used in that node (EXCLUDING THE BODY).

    :param node: The node to look through
    :return: The set of variable ids used inside a node
    """

    args = set()

    # base case 1, stop when the parameter has an ID
    if hasattr(node, "id"):
        args.add(node.id)
    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "replace" and len(node.args) == 2 and node.args[0].value == ";" and not node.args[
                                                                                                             1].value == ";":
                return args

        # resolveCall(node)
    elif hasattr(node, "elts"):
        for subarg in node.elts:
            for subsubarg in get_all_vars(subarg):
                args.add(subsubarg)

    elif isinstance(node, ast.Dict):
        for subarg in node.values:
            for subsubarg in get_all_vars(subarg):
                args.add(subsubarg)

    elif isinstance(node, ast.BinOp):
        for l_subarg in get_all_vars(node.left):
            args.add(l_subarg)
        for r_subarg in get_all_vars(node.right):
            args.add(r_subarg)

    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            for subarg in get_all_vars(value):
                args.add(subarg)

    elif isinstance(node, ast.FormattedValue):
        for subargs in get_all_vars(node.value):
            args.add(subargs)

    elif hasattr(node, "args"):
        args.add(node)
        # for arg in node.args:
        #    for subarg in get_all_vars(arg):
        #        args.add(subarg)

    elif hasattr(node, "value"):
        for subarg in get_all_vars(node.value):
            args.add(subarg)

    return args


def get_all_target_values(node: ast.Assign) -> tuple:
    """
    Gets the variables used in the assignment of each target.

    :param node: The assignment node
    :return: The list of values for each target, empty set signifies no variables
    """
    val_lst = []  # collect all variables mentioned for each assignment
    try:
        for val in node.value.elts:
            val_lst.append(get_all_vars(val))
        if len(val_lst) == 0:
            val_lst.append(set())
    except AttributeError:
        val_lst.append(get_all_vars(node.value))

    return val_lst, 0


def get_inner_scope_assignments(index, assignments) -> tuple:
    """
    Helper function for the obtaining of the assignment nodes in an inner scope.

    :param index: Indexer
    :param assignments: Previous assignment nodes
    :return: New indexer, and new assignments
    """

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
            if len(stack) == 0:
                index += 1
                break

        inner_assignments[assignment_ind].append(node)
        index += 1

    return index - 1, inner_assignments
