import ast
from pathlib import Path

from evase.structures.projectstructure import ProjectAnalysisStruct

prjroot1_filename = Path(Path(__file__).parent, 'resources', 'prjstructtest')
prjroot2_filename = Path(Path(__file__).parent, 'resources', 'demo')
prjroot3_filename = Path(Path(__file__).parent, 'resources', 'webgoat')
scres1_filename = Path(Path(__file__).parent, 'resources', 'screstest.py')
safe1_filename = Path(Path(__file__).parent, 'resources', 'sql_injection_safe1.py')
safe2_filename = Path(Path(__file__).parent, 'resources', 'sql_injection_safe2.py')
vul1_filename = Path(Path(__file__).parent, 'resources', 'sql_injection_vul1.py')
vul2_filename = Path(Path(__file__).parent, 'resources', 'sql_injection_vul2.py')
vul3_filename = Path(Path(__file__).parent, 'resources', 'sql_injection_vul3.py')
vul4_filename = Path(Path(__file__).parent, 'resources', 'sql_injection_vul4.py')
vul5_filename = Path(Path(__file__).parent, 'resources', 'sql_injection_vul5.py')
vul6_filename = Path(Path(__file__).parent, 'resources', 'sql_injection_vul6.py')


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
