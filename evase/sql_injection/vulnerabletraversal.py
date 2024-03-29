from typing import Collection, List, Set, Dict
import ast
from collections import deque

from evase.depanalyze.codetraversalnode import CodeTraversalNode
from evase.depanalyze.searching import FunctionCallFinder as UsesFinder
import evase.sql_injection.injectionutil as injectionutil
from evase.util.logger import AnalysisLogger
import networkx as nx


def copy_list_map_set(list_map_set):
    """
    Copy a map to list map.

    :param list_map_set: The set
    :return: List map
    """
    copy = []
    for map_set in list_map_set:
        copy.append(map_set.copy())
    return copy


def determine_vul_params_location(vul_set: set, func_node):
    """
    Determines the vulnerable parameters of a function definition given a set of vulnerable variables.
    Checks the parameters of the function definition node and compares them with those of the vulnerable set.

    :param vul_set: The vulnerable set of variables
    :param func_node: The function definition node
    :return: Function parameters, and a list of indices of parameters in the function that are vulnerable
    """
    params = injectionutil.get_function_params(func_node)
    lst = []
    for i in range(len(params)):
        if params[i] in vul_set:
            lst.append(i)
    return params, lst


def make_vul_path_graph(vul_paths: Dict) -> nx.DiGraph:
    """
    Turn a mapping of vulnerable paths to a graph.

    :param vul_paths: The mapping of ending nodes to vulnerable paths
    :return: A NetworkX path graph
    """
    graph = nx.DiGraph()

    for pathname, paths in vul_paths.items():
        for path in paths:
            if len(path) >= 1:
                last_node = path[0]
                last_node.add_to_graph(graph)
                for i in range(1, len(path)):
                    node = path[i]
                    node.add_to_graph(graph)

                    # add edge
                    if not graph.has_edge(str(last_node), str(node)):
                        graph.add_edge(str(last_node), str(node))

                    last_node = node

    return graph


def traversal_from_exec(
        uses_finder: UsesFinder,
        assignments: List[ast.Assign],
        func_node,
        injection_vars: Collection[ast.Name],
        module_name: str,
        start_from: ast.Call = None
):
    """
    Perform the breadth-first search algorithm.
    The algorithm starts from the current

    :param uses_finder: A uses finder instance (configured with current project)
    :param assignments: The list of initial assignments to look out for
    :param func_node: The function node that the vulnerable statement is in
    :param injection_vars: The collection of variables in the vulnerable statement
    :param module_name: The name of the current module
    :param start_from: The node containing the vulnerable statement
    :return: A mapping of ending nodes to their vulnerable paths
    """

    # allow to continuously add to the
    visited_func = set()
    queue = deque()

    # print("start of bfs")
    AnalysisLogger().info("starting breadth-first search traversal.")
    vulnerable_vars = set()

    start = CodeTraversalNode(module_name, func_node=func_node, assignments=assignments, variables=injection_vars,
                              from_node=start_from)
    parent_nodes = {
        start: [[start]]
    }

    queue.append(start)
    vul_endpoints = []

    while len(queue) != 0:
        node = queue.popleft()
        AnalysisLogger().info(f"visiting func ---------------------- {str(node)}")

        if node.func_node is None:
            continue

        vulnerable_vars = collect_vulnerable_vars(node.func_node, node.assignments, [{}], [{}],
                                                  node.variables)

        if node.is_endpoint:
            if len(vulnerable_vars) > 0:
                AnalysisLogger().info(f"the endpoint {str(node)} is vulnerable.")
                vul_endpoints.append(node)
                continue
            else:
                AnalysisLogger().info(f"the endpoint {str(node)} is not vulnerable.")
                continue

        else:
            param_indexes_vulnerable = determine_vul_params_location(vulnerable_vars, node.func_node)
            if param_indexes_vulnerable == None:
                continue

            if node.func_node is not None:
                uses_finder.reset_same_project()
                uses_finder.module_name = node.module_name
                uses_finder.func_name = node.func_node.name
                uses_finder.process()

                for nodeNext in uses_finder.function_uses:

                    # stop recursion from breaking the program
                    if nodeNext.func_node == node.func_node:
                        continue

                    if nodeNext in visited_func:
                        continue

                    injection_vars = nodeNext.variables
                    ind = 0
                    inj = set()
                    while ind < len(injection_vars):
                        if ind in param_indexes_vulnerable[1] and len(injection_vars[ind]) != 0:
                            inj.update(injection_vars[ind])
                        ind += 1

                    nodeNext.variables = inj
                    if len(inj) == 0: continue  # unique is in set
                    AnalysisLogger().info(f"\tadding ------------- {str(nodeNext)}")
                    # print("     adding------------- " + nodeNext.get_func_node().name)
                    queue.append(nodeNext)

                    if node in parent_nodes:
                        if nodeNext in parent_nodes:
                            for path in parent_nodes[node]:
                                lst = path.copy()
                                lst.append(nodeNext)
                                parent_nodes[nodeNext].append(lst)
                        else:
                            parent_nodes[nodeNext] = []
                            for path in parent_nodes[node]:
                                lst = path.copy()
                                lst.append(nodeNext)
                                parent_nodes[nodeNext].append(lst)
                    else:
                        raise ValueError("There was an error with tracking the breadth-first search paths.")

    AnalysisLogger().info("breath-first search traversal ended.")
    vul_paths = parent_nodes.copy()
    for key in parent_nodes:
        if key not in vul_endpoints:
            try:
                del vul_paths[key]
            except KeyError:
                pass

    return vul_paths


def collect_vulnerable_vars(
        func_node,
        assignments,
        possible_marked_var_to_params,
        var_type_lst,
        injection_vars={}
):
    """
    Collect the possibly vulnerable variables in a piece of code.

    :param func_node: The function node containing vulnerable statement(s)
    :param assignments: The list of assignments in the code
    :param possible_marked_var_to_params: Possible marked variables (recursive function)
    :param var_type_lst: Possible marked variable types (recursive functions)
    :param injection_vars: Injectable variables in the vulnerable statement(s)
    :return: Vulnerable variables collection
    """
    vulnerable = set()  # params
    parameters = injectionutil.get_function_params(func_node)
    #               possible flow         possible flow
    # marked_lst [{a ->{param1, param2}}, {a->{param3}}]      list<Map<string, set>>
    # var_type_lst [{a -> [Integer]},{a -> [class1,class2]}]

    index = 0
    while index < len(assignments):
        node = assignments[index]

        if isinstance(node, ast.Assign):
            # variables being assigned a value
            target_lst = injectionutil.get_all_targets(node)
            # values of variables being assigned
            val_lst, target_type = injectionutil.get_all_target_values(node)

            for i in range(len(target_lst)):  # for each variable being assigned
                target_variable = target_lst[i]

                for j in range(
                        len(possible_marked_var_to_params)):  # update all possible marked variables to params, for target_variable
                    marked_new = set()
                    for val in val_lst[i]:  # values of variables being assigned to corresponding target_variable

                        # get parameters that val is equal to and add to marked_new
                        if val in possible_marked_var_to_params[j]:
                            marked_new = marked_new.union(possible_marked_var_to_params[j][val])
                        elif val in parameters:
                            marked_new.add(val)

                    possible_marked_var_to_params[j][target_variable] = marked_new

        elif isinstance(node, ast.Return):
            possible_marked_var_to_params.clear(), var_type_lst.clear()
            break

        elif node == "if" or node == "while" or node == "for":
            index, inner_scope_assignments = injectionutil.get_inner_scope_assignments(index, assignments)
            prev_marked_lst = copy_list_map_set(possible_marked_var_to_params)
            prev_var_type_lst = copy_list_map_set(var_type_lst)

            for inner_scope_assignment in inner_scope_assignments:
                copy_marked_lst = copy_list_map_set(prev_marked_lst)
                copy_var_type_lst = copy_list_map_set(prev_var_type_lst)

                # determine marked_lst in inner function, new_vulnerable is for when function returns are being analyzed
                new_vulnerable = collect_vulnerable_vars(func_node, inner_scope_assignment, copy_marked_lst,
                                                         copy_var_type_lst)

                # add inner scope marked_lst to previous possible_marked_var_to_params
                possible_marked_var_to_params.extend(copy_marked_lst)
                var_type_lst.extend(copy_var_type_lst)
                vulnerable = vulnerable.union(new_vulnerable)
        index += 1

    # if injection_vars -> cursor.execute() determine if vars used in injection are dangerous
    if len(injection_vars) != 0:
        for val in injection_vars:
            for marked in possible_marked_var_to_params:
                if val not in marked and val in parameters:
                    vulnerable.add(val)
                elif val in marked:
                    for vulnerable_param in marked[val]:
                        vulnerable.add(vulnerable_param)

            if len(possible_marked_var_to_params) == 0 and val in parameters:
                vulnerable.add(val)

    return vulnerable
