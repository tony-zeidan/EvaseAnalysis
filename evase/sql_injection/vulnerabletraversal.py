from typing import Collection, List
import ast
from collections import deque
from evase.depanalyze.node import Node
import evase.depanalyze.searching as searching
import evase.sql_injection.injectionutil as injectionutil
import networkx as nx


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


def get_node_name(node):
    return f'{node.get_module_name()}.{node.get_func_node().name}'


def get_node_identifier(node):
    return f'{node.get_module_name()} {node.get_func_node().name} {len(node.get_assignments())}'


def add_graph_node(g, node):
    g.add_node(str(node), vars=node.get_injection_vars(), assignments=node.get_assignments(), func=node.get_func_node(), endpoint=node.is_endpoint)

class VulnerableTraversalChecker:
    def traversal_from_exec(self, assignments: List[ast.Assign], func_node, injection_vars: Collection[ast.Name],
                            project_struct, module):

        # allow to continuously add to the
        visited_func = set()  # unique with func name, module and num assignments
        queue = deque()
        modules = project_struct.get_module_structure()

        print("start of bfs")
        vulnerable_vars = set()

        graph = nx.DiGraph()
        start = Node(func_node, assignments, injection_vars, module)
        start.add_to_graph(graph)
        queue.append(start)

        while len(queue) != 0:
            node = queue.popleft()

            identifier = get_node_identifier(node)
            visited_func.add(identifier)
            print("visiting func ----------------------", node.get_func_node().name)
            vulnerable_vars = self.collect_vulnerable_vars(node.get_func_node(), node.get_assignments(), [{}], [{}],
                                                           node.get_injection_vars())

            if node.is_endpoint:
                if len(vulnerable_vars) > 0:
                    print("api ", node.get_func_node().name, " is vulnerable")
                    break
            else:
                param_indexes_vulnerable = determine_vul_params_location(vulnerable_vars, node.get_func_node())
                if param_indexes_vulnerable == None: continue

                for nodeNext in searching.get_function_uses(modules, node.get_func_node().name, node.get_module_name()):

                    if get_node_identifier(nodeNext) in visited_func:
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
                    nodeNext.add_to_graph(graph)

        if len(vulnerable_vars) == 0:
            return None
        else:
            node.add_to_graph(graph)
            return graph

    def collect_vulnerable_vars(self, func_node, assignments, possible_marked_var_to_params, var_type_lst,
                                injection_vars={}):
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
                        # var_type_lst[j][target] = target_type[j]
                # print(possible_marked_var_to_params)

            elif isinstance(node, ast.Return):
                # if len(injection_vars) == 0:
                #   for val in return:
                #       for vulnerable_param in marked_lst[val]:
                #           vulnerable.add(vulnerable_param)
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
                    # print("here")
                    # print(inner_scope_assignment)
                    # print(copy_marked_lst)
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
