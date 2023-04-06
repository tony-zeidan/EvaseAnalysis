import evase.structures.analysisperformer as ap
import evase.util.fileutil as futil

import unittest
from tests.testutil import *


class TestProjectAnalysisPerformer(unittest.TestCase):
    """
    Tests for the functionality of the analysis performer.
    """

    def setUp(self):
        """
        Set up initial testing structures.
        """
        
        self.test_struct1 = ap.AnalysisPerformer(
            "test-demo",
            prjroot3_filename,
            output_path=r"C:\Users\tonyz\AppData\Local\Temp\EVASE_DEMO222_1c70afaa-074f-422c-89bb-44bf02a74d89_w9dlbc3k"
        )
        self.test_struct2 = ap.AnalysisPerformer(
            "test-demo",
            prjroot2_filename,
            output_path=r"C:\Users\tonyz\AppData\Local\Temp\EVASE_DEMO222_1c70afaa-074f-422c-89bb-44bf02a74d89_w9dlbc3k"
        )

    def test_dependency_graph(self):
        """
        Tests the ability of the analysis performer to construct the proper graph.
        """

        self.test_struct1.perform_analysis()
        results = self.test_struct1.get_results()

        dirpath = Path(prjroot3_filename)
        all_package_names = [name for name, _ in futil.get_project_module_names(dirpath)]
        nodes_present = [x['id'] for x in results['graph']['total']['nodes']]

        exclusion_list = ["flask_webgoat.templates.hello"]
        for exc in exclusion_list:
            all_package_names.remove(exc)

        # exclude files when they have no incoming or outgoing dependencies
        self.assertTrue(
            all([x in nodes_present for x in all_package_names])
        )

        self.test_struct2.perform_analysis()
        results = self.test_struct2.get_results()

        dirpath = Path(prjroot2_filename)
        all_package_names = [name for name, _ in futil.get_project_module_names(dirpath)]
        nodes_present = [x['id'] for x in results['graph']['total']['nodes']]

        # exclude files when they have no incoming or outgoing dependencies
        exclusion_list = ["backend.__init__"]
        for exc in exclusion_list:
            all_package_names.remove(exc)

        self.assertTrue(
            all([x in nodes_present for x in all_package_names])
        )
