import evase.structures.analysisperformer as ap
import evase.structures.projectstructure as prj
from pathlib import Path
import unittest
from testutil import *

from pprint import pprint

class TestProjectAnalysisPerformer(unittest.TestCase):

    def setUp(self):
        self.test_struct1 = ap.AnalysisPerformer(
            "test-demo",
            prjroot3_filename
        )
        self.test_struct2 = ap.AnalysisPerformer(
            "test-demo",
            prjroot2_filename
        )

    def test_dependency_graph(self):
        """
        Tests the ability of the analysis performer to construct the proper graph.
        """

        self.test_struct1.perform_analysis()
        results = self.test_struct1.get_results()

        dirpath = Path(prjroot3_filename)
        all_files = dirpath.glob("**/*.py")
        init_preset = prj.has_init_file(dirpath)
        all_package_names = [prj.package_name(file, dirpath, initial_init=init_preset) for file in all_files]
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

        pprint(results)

        dirpath = Path(prjroot2_filename)
        all_files = dirpath.glob("**/*.py")
        init_preset = prj.has_init_file(dirpath)
        all_package_names = [prj.package_name(file, dirpath, initial_init=init_preset) for file in all_files]
        nodes_present = [x['id'] for x in results['graph']['total']['nodes']]

        # exclude files when they have no incoming or outgoing dependencies
        exclusion_list = ["backend.__init__"]
        for exc in exclusion_list:
            all_package_names.remove(exc)

        self.assertTrue(
            all([x in nodes_present for x in all_package_names])
        )

