from graphviz import Digraph
# Create Digraph object

class Output(object):
    def __init__(self) -> None:
        self.dot = None
    
    def visualize_tree(self, tree) -> None:
        def add_nodes_edges(tree, dot=None):
            # Create Digraph object
            if dot is None:
                dot = Digraph()
                dot.node(name=str(tree), label=str(tree.value))

            # Add nodes
            if tree.left:
                dot.node(name=str(tree.left) ,label=str(tree.left.value))
                dot.edge(str(tree), str(tree.left))
                dot = add_nodes_edges(tree.left, dot=dot)
                
            if tree.right:
                dot.node(name=str(tree.right) ,label=str(tree.right.value))
                dot.edge(str(tree), str(tree.right))
                dot = add_nodes_edges(tree.right, dot=dot)

            return dot
        
        # Add nodes recursively and create a list of edges
        self.dot = add_nodes_edges(tree)
        # dot.view()
        # dot.render(outfile='./Output_tree.svg').replace('\\', '/')
    
    def save_img(self, output_name) -> None:
        
        if self.dot != None:
            self.dot.render(outfile=f'./{output_name}svg').replace('\\', '/')