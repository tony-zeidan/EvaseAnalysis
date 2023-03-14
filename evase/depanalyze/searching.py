import ast
from evase.depanalyze.functioncallfinder import FunctionCallFinder
from evase.structures.modulestructure import ModuleAnalysisStruct
from evase.structures.projectstructure import ProjectAnalysisStruct, resolve_project_imports, dir_to_module_structure


def get_function_uses(prj_struct, func_name: str, module_name: str):
    """
    Get all the uses for a function call, and find vulnerable variables.

    :param prj_struct: The project structure object containing the dependency graph
    :param func_name: The function to search uses of
    :param module_name: The name module that the function was found in
    :return: The newly found vulnerable variables
    """

    new_vuls = []
    for key in prj_struct:
        module_struct = prj_struct[key]
        case, asname = 0, None
        if not key == module_name:
            case, asname = differentiate_imports(module_struct, func_name, module_name)
        else:
            case = 2

        # for each case run a node visitor and tell the node visitor it's target to look for
        # reference sql injection algo development notion, page api.py(for test vul func calls) for more information of the four cases.
        #print(f'----   scaning vulnerable usages [{module_name}].[{func_name}] in {module_struct.get_name()} ----')
        func_target = func_name
        module_target = module_name
        if case == 0:
            #print(f"CASE 0: no vulnerable usage found")
            continue

        # No modification needed for case 1

        elif case == 2:
            #print(f"CASE 2: vulnerable function found imported, next step look for function calls [{func_name}]")
            module_target = None
        elif case == 3:
            #print(f"CASE 3: vulnerable function found imported using AS, next step look for function calls [{asname}]")
            module_target = None
            func_target = asname

        elif case == 4:
            #print(f"CASE 4: vulnerable class found imported using AS, next step look for [{asname}.{func_name}]")
            module_target = asname
        #print(f"passing in [{module_target}, {func_target}]")
        call_finder = FunctionCallFinder(key, module_target, func_target)
        call_finder.visit(module_struct.ast_tree)

        for node in call_finder.found_calling_lst:
            new_vuls.append(node)

    return new_vuls


def differentiate_imports(mdl_struct: ModuleAnalysisStruct, vul_func: str, vul_module_name: str):
    """
    :param mdl_struct: The module structure that we are looking at
    :param vul_func: The vulnerable function name as a String, we want to know in what way this function is imported, or not at all.
    :param vul_module_name: The vulnerable module name as a String, we want to know in what way this module is imported, or not at all
    :return:

    """

    # function can tell us if the vulnerale is imported as function or module
    local_import = mdl_struct.get_local_imports()
    module_import = mdl_struct.get_module_imports()
    # case1, importing entire module
    if vul_module_name in local_import.keys() or vul_module_name in module_import.keys():
        return 1, vul_module_name

    # case2, importing vulnerable function
    if vul_func in local_import.keys() or vul_func in module_import.keys():
        return 2, vul_func

    # case3, importing vul function with AS
    for key in local_import:
        func_as_name = key
        class_name, original_func_name = local_import[key]
        #print("Checking 3" + class_name, original_func_name)
        if original_func_name == vul_func:
            return 3, func_as_name

    for key in module_import:
        func_as_name = key
        class_name, original_func_name = module_import[key]
        #print("[" + class_name, ',', original_func_name + "]")
        if original_func_name == vul_func:
            return 3, func_as_name

    # case4, importing entire module with AS
    for key in local_import:
        class_name, class_as_name = local_import[key]
        #print("Checking 4" + class_name, class_as_name)

        if class_name == vul_module_name:
            return 4, class_as_name

    for key in module_import:
        class_name, class_as_name = module_import[key]
        #print("Checking 4" + class_name, class_as_name)
        if class_name == vul_module_name:
            return 4, class_as_name

    # not found related import, this file is not related for this vul
    return 0, None


def search_calling_tree(path: str, initial_vuls: list):
    """

    :param path:
    :param initial_vuls:
    :return:
    """

    vul_list = initial_vuls  # storing uncalled vulnerable function
    uncalled_vul_list = []  # storing vulnerable function that has been called
    asts = dir_to_module_structure(path)
    resolve_project_imports(path, asts)
    running = True  # stop when we don't find any calling of vulnerable function

    while running:
        running = False
        new_vul_list = []
        for vul in vul_list:
            func = vul['function']
            module = vul['module']
            temp_list = get_function_uses(asts, func, module)
            if (len(temp_list)):
                running = True
            new_vul_list.extend(temp_list)
        vul_list = new_vul_list
        print_vul_list(vul_list)


def print_vul_list(vul_list):
    """

    :param vul_list:
    :return:
    """

    print("====== vul_list update =======")
    for vul in vul_list:
        print(f"module: {vul['module']}, function: {vul['function']}")
