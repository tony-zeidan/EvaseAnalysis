import os
import pathlib

import evase.structures.analysisperformer as ap


if __name__ == '__main__':
    res_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'resources')
    test1 = os.path.join(res_path, 'demo')
    test2 = os.path.join(res_path, 'flask_webgoat')
    apr = ap.AnalysisPerformer("demo", test2)
    apr.perform_analysis()

