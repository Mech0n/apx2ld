from os import makedirs
from os.path import exists

from graphviz import Digraph
from rich.console import Console

# Create Digraph object

class Output(object):
    def __init__(self, output_name, basedir="release") -> None:
        self.dot = None
        self.basedir = basedir
        self.output_name = output_name

        if not exists(self.basedir):
            makedirs(self.basedir)
    
    def save_img(self) -> None:
        
        if self.dot != None:
            self.dot.render(outfile=f'./{self.basedir}/{self.output_name}.svg').replace('\\', '/')
            with Console() as c:
                c.print(f"[logs] [Module] Output [Method] Save result img as ./{self.basedir}/{self.output_name}.svg")
                c.print(f"[logs] [Module] Output [Method] You can get gv file as ./{self.basedir}/{self.output_name}.gv")

    def add_nodes_edges(self, tree) -> None:
        # print(id(dot))
        # Create Digraph object
        if self.dot is None:
            with Console() as c:
                c.print(f"[Module] Output [Method] add_nodes_edges: Digraph object has not been init!")
            return

        if tree.right:
            self.dot.node(name=str(tree.right) ,label=str(tree.right.value))
            self.dot.edge(str(tree), str(tree.right))
            self.add_nodes_edges(tree.right)
        
        # Add nodes
        if tree.left:
            self.dot.node(name=str(tree.left) ,label=str(tree.left.value))
            self.dot.edge(str(tree), str(tree.left))
            self.add_nodes_edges(tree.left)

    def visualize_tree(self, trees):
        if self.dot is None:
            self.dot = Digraph()
        
        # Add nodes recursively and create a list of edges
        for tree in trees:
            self.dot.node(name=str(tree), label=str(tree.value))
            self.add_nodes_edges(tree)

        return self.dot