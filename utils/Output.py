from graphviz import Digraph

# Create Digraph object

class Output(object):
    def __init__(self) -> None:
        self.dot = None
    
    def save_img(self, output_name) -> None:
        
        if self.dot != None:
            self.dot.render(outfile=f'./{output_name}svg').replace('\\', '/')

    def add_nodes_edges(self, tree) -> None:
        # print(id(dot))
        # Create Digraph object
        if self.dot is None:
            # TODO: Error msg
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