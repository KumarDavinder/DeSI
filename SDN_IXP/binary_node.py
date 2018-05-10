class BinaryNode:

    def __init__(self, value, left, right):
        self.value = value
        self.left = left
        self.right = right

    def getValue(self):
        return self.value

    def getLeft(self):
        return self.left

    def getRight(self):
        return self.right

    def setValue(self, value):
        self.value = value

    def setLeft(self, left):
        self.left = left

    def setRight(self, right):
        self.right = right
