import unittest
from testutil import *

import os

from evase.structures.projectstructure import dir_to_module_structure


class TestProjectAnalysisStruct(unittest.TestCase):
    """
    Tests the functionality of the project structure object.
    """

    def setUp(self):
        """
        Set up project structure.
        """
        self.test_struct1 = get_projectstruct("test1", prjroot1_filename)

    def test_project_root(self):
        """
        Test the root of the structure.
        """

        self.assertEqual(prjroot1_filename, self.test_struct1.root)

    def test_project_struct_dirs(self):
        """
        Test the ability to make the module structure.
        """

        md_struct = self.test_struct1.structure

        total_len = 0
        for root, dirs, files in os.walk(prjroot1_filename):
            total_len += len([f for f in files if f.endswith(".py")])

        self.assertEqual(total_len, len(md_struct), "Module structure didn't have all of the .py files in it.")

    def test_dir_to_module_structure(self):
        """
        Test made specifically for the module structure of the test project 'prjstructtest'.
        """
        test_mdl_struct = dir_to_module_structure(prjroot1_filename)
        self.assertIn('prjstructtest.runner', test_mdl_struct)
        self.assertIn('prjstructtest.__init__', test_mdl_struct)
        self.assertIn('prjstructtest.test.__init__', test_mdl_struct)
        self.assertIn('prjstructtest.util.helper', test_mdl_struct)
        self.assertIn('prjstructtest.util.__init__', test_mdl_struct)
        self.assertIn('prjstructtest.util.moreutil.helper2', test_mdl_struct)
        self.assertIn('prjstructtest.util.moreutil.__init__', test_mdl_struct)

