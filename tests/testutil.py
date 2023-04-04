import ast
from pathlib import Path

from evase.structures.projectstructure import ProjectAnalysisStruct

prjroot1_filename = Path('resources/prjstructtest').absolute()
prjroot2_filename = Path('resources/demo').absolute()
prjroot3_filename = Path('resources/webgoat').absolute()
scres1_filename = Path('resources/screstest.py').absolute()
safe1_filename = Path('resources/sql_injection_safe1.py').absolute()
safe2_filename = Path('resources/sql_injection_safe2.py').absolute()
vul1_filename = Path('resources/sql_injection_vul1.py').absolute()
vul2_filename = Path('resources/sql_injection_vul2.py').absolute()
vul3_filename = Path('resources/sql_injection_vul3.py').absolute()
vul4_filename = Path('resources/sql_injection_vul4.py').absolute()
vul5_filename = Path('resources/sql_injection_vul5.py').absolute()
vul6_filename = Path('resources/sql_injection_vul6.py').absolute()


def get_ast_from_filename(filename: str) -> ast.AST:
    """
    Obtain the AST for the given file.

    :param filename: The path to the file
    :return: The AST structure
    """
    with open(filename, "r") as af:
        return ast.parse(af.read())


def get_projectstruct(name: str, dirpath: str) -> ProjectAnalysisStruct:
    """
    Get the project structure object for a given path.

    :param name: Arbitrary name for the project
    :param dirpath: The path to the project root
    :return: The project structure object
    """
    return ProjectAnalysisStruct(
        name,
        dirpath
    )
