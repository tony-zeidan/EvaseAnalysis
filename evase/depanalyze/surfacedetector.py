import ast


class SurfaceLevelVisitor(ast.NodeVisitor):
    def __init__(self):
        self.surface_names = set()

    def generic_visit(self, node):
        if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
            return

        if isinstance(node, ast.Module):
            super().generic_visit(node)
        elif isinstance(node, ast.Assign):
            # only one assignment
            if hasattr(node.targets[0], 'id'):
                for val in node.targets:
                    self.surface_names.add(val.id)
            # multiple assignments
            else:
                for val in node.targets[0].elts:
                    self.surface_names.add(val.id)
        else:
            if hasattr(node, 'name'):
                self.surface_names.add(node.name)

    def get_surface_names(self):
        return self.surface_names

    def clear_surface_names(self):
        self.surface_names.clear()
