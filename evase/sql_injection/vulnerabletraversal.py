from typing import Collection, List, Set
import ast
from collections import deque
from evase.depanalyze.node import Node
from evase.depanalyze.searching import FunctionCallFinder as UsesFinder
import evase.sql_injection.injectionutil as injectionutil
import networkx as nx

from pprint import pprint

from evase.structures.projectstructure import ProjectAnalysisStruct


def copy_list_map_set(list_map_set):
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


class VulnerableTraversalChecker:
    def __init__(
            self,
            prj_struct: ProjectAnalysisStruct,
    ):
        self.prj_struct = prj_struct

    def traversal_from_exec(self, assignments: List[ast.Assign], func_node, injection_vars: Collection[ast.Name]
                            , module_name: str, start_from: ast.Call = None):

        # allow to continuously add to the
        visited_func = set()
        visited_func_reprs = {}
        queue = deque()

        # print("start of bfs")
        vulnerable_vars = set()

        graph = nx.DiGraph()
        start = Node(module_name, func_node=func_node, assignments=assignments, injection_vars=injection_vars,
                     from_node=start_from)

        parent_nodes = {
            start: [[start]]
        }

        start.add_to_graph(graph)
        queue.append(start)

        vul_endpoints = []

        while len(queue) != 0:
            node = queue.popleft()

            # curr_path = curr_path[str(node)]

            node.get_func_node()
            visited_func.add(node.__repr__())

            # print("visiting func ----------------------", str(node))

            if node.get_func_node() is None:
                continue

            vulnerable_vars = self.collect_vulnerable_vars(node.get_func_node(), node.get_assignments(), [{}], [{}],
                                                           node.get_injection_vars())

            if node.is_endpoint:
                print("ENDPOINT FOUND")
                print(node)

                if len(vulnerable_vars) > 0:
                    print("api", node.get_func_node().name, "is vulnerable")
                    vul_endpoints.append(node)
                    continue
                else:
                    # delete the non-vulnerable traversal branch
                    print("The endpoint isn't vulnerable.")

            else:
                param_indexes_vulnerable = determine_vul_params_location(vulnerable_vars, node.get_func_node())
                if param_indexes_vulnerable == None:
                    continue

                for nodeNext in UsesFinder.find_function_uses(self.prj_struct, node.get_module_name(),
                                                              node.get_func_node().name):

                    # stop recursion from breaking the program
                    if nodeNext.get_func_node() == node.get_func_node():
                        continue

                    if nodeNext.__repr__() in visited_func:
                        if not graph.has_edge(str(node), str(nodeNext)):
                            graph.add_edge(str(node), str(nodeNext))
                        continue

                    injection_vars = nodeNext.get_injection_vars()
                    ind = 0
                    inj = set()
                    while ind < len(injection_vars):
                        if ind in param_indexes_vulnerable[1] and len(injection_vars[ind]) != 0:
                            inj.update(injection_vars[ind])
                        ind += 1

                    nodeNext.set_injection_vars(inj)
                    if len(inj) == 0: continue  # unique is in set
                    print("     adding------------- " + nodeNext.get_func_node().name)
                    queue.append(nodeNext)

                    if node in parent_nodes:
                        print(nodeNext.__repr__())

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
                        raise ValueError("ERROR parent not in paths")

                    nodeNext.add_to_graph(graph)
                    if not graph.has_edge(str(node), str(nodeNext)):
                        graph.add_edge(str(node), str(nodeNext))

        print("PATHS", parent_nodes)

        vul_paths = parent_nodes.copy()
        for key in parent_nodes:
            if key not in vul_endpoints:
                try:
                    del vul_paths[key]
                except KeyError:
                    print("No such key found.")
                    pass

        print("ALT PATHS", parent_nodes)

        node_data = {}
        for endpoint, paths in vul_paths.items():
            for path in paths:
                for node in path:
                    if str(node) not in node_data:
                        node_data[str(node)] = {
                            ''
                        }



    def collect_vulnerable_vars(self, func_node, assignments, possible_marked_var_to_params, var_type_lst,
                                injection_vars={}, is_endpoint: bool = False):
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
                    new_vulnerable = self.collect_vulnerable_vars(func_node, inner_scope_assignment, copy_marked_lst,
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
