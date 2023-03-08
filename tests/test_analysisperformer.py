import os
import pathlib

import evase.structures.analysisperformer as ap


def do_test():
    apr = ap.AnalysisPerformer("demo", r"C:\courses\SYSC_4907\EvaseAnalysis\tests\resources\demo")
    apr.perform_analysis()

