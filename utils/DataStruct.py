class Node(object):

    def __init__(self, value: str, left=None, right=None) -> None:
        self.value = value  # The node value
        self.left = left    # Left child
        self.right = right  # Right child

    def set_value(self, value: str) -> None:
        self.value = value
            