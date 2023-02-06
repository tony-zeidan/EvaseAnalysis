import ast
import unittest
import testutil
import copy

from evase.depanalyze.scoperesolver import ScopeResolver


class TestScopeResolver(unittest.TestCase):

    def setUp(self):
        self.test_file1 = testutil.get_ast_from_filename(testutil.scres1_filename)

    def test_resolverobj(self):
        test_resolver = ScopeResolver()
        classdefs = []
        belongs = []
        funcdefs = []

        for node in ast.walk(self.test_file1):
            if isinstance(node, ast.ClassDef):
                classdefs.append(node)
            elif isinstance(node, ast.FunctionDef):
                nodecpy = copy.deepcopy(node)
                funcdefs.append(node)
                found = False
                for cls in classdefs:
                    for subnode in ast.walk(cls):
                        if subnode == node:
                            found = True
                            belongs.append((cls, nodecpy))
                            break

                if not found:
                    belongs.append((None, nodecpy))

        test_resolver.visit(self.test_file1)

        for node, (cls, fn) in zip(funcdefs, belongs):
            shname = f'{cls.name}.{fn.name}' if cls else fn.name
            self.assertEqual(shname, node.name, "Node name wasn't formatted properly")
