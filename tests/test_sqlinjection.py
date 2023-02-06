from evase.structures.modulestructure import ModuleAnalysisStruct
from evase.structures.projectstructure import ProjectAnalysisStruct
from evase.sql_injection.injectionvisitor import InjectionNodeVisitor

import ast
import os

safe1_filename = 'sql_injection_safe1.py'
safe2_filename = 'sql_injection_safe2.py'
vul1_filename = 'sql_injection_vul1.py'
vul2_filename = 'sql_injection_vul2.py'
vul3_filename = 'sql_injection_vul3.py'
vul4_filename = 'sql_injection_vul4.py'
vul5_filename = 'model.py'
vul6_filename = 'sql_injection_vul6.py'


def get_ast_from_filename(filename: str):
    with open(filename, "r") as af:
        return ast.parse(af.read())

#
# safe1_struct = ModuleAnalysisStruct(safe1_filename, get_ast_from_filename(safe1_filename))
# safe2_struct = ModuleAnalysisStruct(safe2_filename, get_ast_from_filename(safe2_filename))
# vul1_struct = ModuleAnalysisStruct(vul1_filename, get_ast_from_filename(vul1_filename))
# vul1_struct = ModuleAnalysisStruct(vul1_filename, get_ast_from_filename(vul2_filename))
# vul1_struct = ModuleAnalysisStruct(vul1_filename, get_ast_from_filename(vul3_filename))
# vul1_struct = ModuleAnalysisStruct(vul1_filename, get_ast_from_filename(vul4_filename))


def print_execute_funcs(visitor: InjectionNodeVisitor):
    for func_name in visitor.get_execute_funcs():
        print("Execution found in:", func_name)


def get_modulestruct(filename: str):
    tree = get_ast_from_filename(filename)
    return ModuleAnalysisStruct(filename, tree)

def test_get_all_vars():
    path_here = os.path.dirname(os.path.realpath(__file__))
    # astVul5 = get_ast_from_filename(vul5_filename)
    # allVars = injectionutil.get_all_vars(astVul5)
    # print(allVars)
    # test = ProjectAnalysisStruct("parser", "C:/Users/Anthony/Desktop/Desktop/Proj/parser")
    #test = ProjectAnalysisStruct("demonstration", os.path.join(path_here, 'resources', 'demonstration'))

    path_here = os.path.dirname(os.path.realpath(__file__))
    print(path_here)
    demo_code = os.path.join(path_here, 'test', 'resources')

    test = ProjectAnalysisStruct("demonstration", "C:/Users/Anthony/Desktop/Desktop/Proj/evase/backend/test/resources/demo2")
    for m_name, m_struct in test.get_module_structure().items():
        print(m_struct.get_module_imports(), "imports")
        print(m_name)
        visitor = InjectionNodeVisitor(test, m_name)
        visitor.visit(m_struct.get_ast())
        print_execute_funcs(visitor)

    #module_vul5 = test.get_module("find_uses_tests.sql_injection_vul5")
    #modules = test.get_module_structure()
    #print("module+++++++++++")
    #for key in modules.keys():
    #    print(key)
    #    print(modules[key])
    #print("module+++++++++++")
    #visitor = InjectionNodeVisitor(test, "vulnerable_example.sql_injection_vul5")
    #visitor.visit(module_vul5.get_ast())
    #print_execute_funcs(visitor)

if __name__ == '__main__':
    test_get_all_vars()
