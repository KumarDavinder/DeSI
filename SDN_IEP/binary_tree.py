from binary_node import BinaryNode
import json

def create_binary_tree_from_json(condition, rootNode):
    if(str(condition[1]).startswith("[")):
        left = condition[1]
        rootNode.setLeft(BinaryNode(str(left[0]), None, None))
        create_binary_tree_from_json(left, rootNode.getLeft())
    else:
        rootNode.setLeft(BinaryNode(str(condition[1]), None, None))
    if(str(condition[2]).startswith("[")):
        right = condition[2]
        rootNode.setRight(BinaryNode(str(right[0]), None, None))
        create_binary_tree_from_json(right, rootNode.getRight())
    else:
        rootNode.setRight(BinaryNode(str(condition[2]), None, None))
    return rootNode

def get_binary_tree_action(rule):
    condition = rule["condition"]
    action = rule["action"]
    if(str(condition).__contains__(",")):
        rootNode = BinaryNode(str(condition[0]), None, None)
        rootNode = create_binary_tree_from_json(condition, rootNode)
        binary_tree_action = [rootNode, action]
        return binary_tree_action
    else:
        binary_tree_action = [BinaryNode(str(condition), None, None), action]
        return binary_tree_action

def from_json_to_binary_tree_action(pathInputFile):
    with open(pathInputFile) as file_input:
        data = json.load(file_input)
    rules = data["policies"]
    list_binary_tree_action = []
    for rule in rules:
        list_binary_tree_action.append(get_binary_tree_action(rule["policy"]))
    return list_binary_tree_action

def from_binary_tree_only_and_operations(node, resultAND, left, right):
    if(node.getLeft() == None and node.getRight() == None):
        return node.getValue()
    elif(node.getValue().__eq__("AND")):
        left = from_binary_tree_only_and_operations(node.getLeft(), resultAND, left, right)
        right = from_binary_tree_only_and_operations(node.getRight(), resultAND, left, right)
        left = left.replace("  ", " ")
        right = right.replace("  ", " ")
        if (left[-1:].__eq__(' ')):
            left = left[:-1]
        if (right[-1:].__eq__(' ')):
            right = right[:-1]
        for l in left.split(" "):
            for r in right.split(" ") :
                resultAND += l + "_and_" + r + " "
        return resultAND
    else:
        return from_binary_tree_only_and_operations(node.getLeft(), resultAND, left, right) + " " + \
               from_binary_tree_only_and_operations(node.getRight(), resultAND, left, right)



