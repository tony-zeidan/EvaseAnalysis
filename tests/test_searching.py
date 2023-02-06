import unittest

from evase.structures.projectstructure import ProjectAnalysisStruct
from evase.depanalyze.searching import *
from testutil import *


class TestSearching(unittest.TestCase):

    def test_find_function_call_origin(self):
        test_project = ProjectAnalysisStruct("testproject", prjroot1_filename)
        print(test_project.get_module_structure())

        runner_mdl = test_project.get_module('prjstructtest.runner')
        used_mdl = test_project.get_module('prjstructtest.util.helper')

        test_use_node = ast.parse('pretty_print()').body[0].value
        print(test_use_node)

        get_function_call_origin(test_use_node, runner_mdl, test_project)


if __name__ == '__main__':
    unittest.main()
