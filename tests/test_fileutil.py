import evase.util.fileutil as futil

import unittest
from testutil import *


class TestFileUtilities(unittest.TestCase):
    """
    Tests for the functionality of file utility functions.
    """

    def test_package_names1(self):
        """
        Tests the functionality behind generating package names for a set of modules.

        Testing on the custom backend dataset.
        """

        expected_modules = [
            'backend.__init__',
            'backend.app',
            'backend.vul',
            'backend.vul_wrapper'
        ]

        actual_modules, actual_paths = [], []

        test_path = Path(prjroot2_filename).absolute()

        for module_name, path in futil.get_project_module_names(test_path):
            # check that this module is in the expected modules
            self.assertIn(module_name, expected_modules)

            actual_modules.append(module_name)
            actual_paths.append(path)

            # check properties of the file path
            self.assertIsInstance(path, Path)
            self.assertTrue(path.exists())
            self.assertTrue(path.is_relative_to(test_path))

        for module_name in expected_modules:
            self.assertIn(module_name, actual_modules)

    def test_package_names2(self):
        """
        Tests the functionality behind generating package names for a set of modules.

        Testing on the flask webgoat dataset.
        """

        expected_modules = [
            'flask_webgoat.__init__',
            'flask_webgoat.actions',
            'flask_webgoat.auth',
            'flask_webgoat.status',
            'flask_webgoat.ui',
            'flask_webgoat.users',
            'flask_webgoat.templates.__init__',
            'flask_webgoat.templates.hello',
            'flask_webgoat.templates.helper'
        ]

        actual_modules, actual_paths = [], []

        test_path = Path(prjroot3_filename).absolute()

        for module_name, path in futil.get_project_module_names(test_path):
            # check that this module is in the expected modules
            self.assertIn(module_name, expected_modules)

            actual_modules.append(module_name)
            actual_paths.append(path)

            # check properties of the file path
            self.assertIsInstance(path, Path)
            self.assertTrue(path.exists())
            self.assertTrue(path.is_relative_to(test_path))

        for module_name in expected_modules:
            self.assertIn(module_name, actual_modules)
