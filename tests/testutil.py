import ast

from backend.depanalyze.modulestructure import ModuleAnalysisStruct

prjroot1_filename = 'resources/prjstructtest'
scres1_filename = 'resources/screstest.py'
safe1_filename = 'resources/sql_injection_safe1.py'
safe2_filename = 'resources/sql_injection_safe2.py'
vul1_filename = 'resources/sql_injection_vul1.py'
vul2_filename = 'resources/sql_injection_vul2.py'
vul3_filename = 'resources/sql_injection_vul3.py'
vul4_filename = 'resources/sql_injection_vul4.py'
vul5_filename = 'resources/sql_injection_vul5.py'
vul6_filename = 'resources/sql_injection_vul6.py'


def get_ast_from_filename(filename: str) -> ast.AST:
    with open(filename, "r") as af:
        return ast.parse(af.read())


def get_modulestruct(filename: str) -> ModuleAnalysisStruct:
    return ModuleAnalysisStruct(filename, get_ast_from_filename(filename))
