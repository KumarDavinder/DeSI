import networkx as nx
import ipaddr


def get_quadruples(rule):
    quadruples = []
    rules = rule.split(" ")
    for r in rules:
        quadruples.append(get_quadruple(r))
    return quadruples

def get_quadruple(rule):
    matches = rule.split("_and_")
    quadruple = []
    quadruple.insert(0, "*")
    quadruple.insert(1, "*")
    quadruple.insert(2, "*")
    quadruple.insert(3, "*")
    for match in matches:
        match = str(match)
        if (match.__contains__("tcp_src")):
            quadruple[0] = match
        elif (match.__contains__("tcp_dst")):
            quadruple[1] = match
        elif (match.__contains__("ipv4_src")):
            quadruple[2] = match
        elif (match.__contains__("ipv4_dst")):
            quadruple[3] = match
    return quadruple


def get_graph_dependence(list_rule_action):
    list_quadruples = []
    GD = nx.DiGraph()
    x = 0
    """create quadruple and nodes of graph"""
    for rule_action in list_rule_action:
        list_quadruples.append(get_quadruples(rule_action[0]))
        GD.add_node(x)
        x = x + 1
    for i in range(1, list_quadruples.__len__()):
        node_i = list_quadruples[i]
        for j in range(0, i):
            node_j = list_quadruples[j]
            if (check_j_subset_i(node_j, node_i)):
                GD.add_edge(i, j)
                print ("under " + str(i) + " --> " + str(j))
            elif ((check_j_not_superset_i_and_intersection_i_j(node_i, node_j))):
                print ("intersection " + str(i) + " --> " + str(j))
                GD.add_edge(i, j)
    return GD


def get_dictionary_of_graph_dependence(list_rule_action):
    graph_dependece = get_graph_dependence(list_rule_action)
    graph_dependence_dictionary = {}
    for index in range(0, graph_dependece.nodes.__len__()):
        graph_dependence_dictionary.update({index: []})
    for edge in graph_dependece.edges:
        graph_dependence_dictionary.get(int(str(edge).split(",")[0].split("(")[1])).append(
            int(str(edge).split(",")[1].split(")")[0][1:]))
    return graph_dependence_dictionary

def check_j_subset_i(node_j, node_i):
    for i in node_i:
        for j in node_j:
            if(first_subset_second(j,i)):
                return True
    return False

def check_j_not_superset_i_and_intersection_i_j(node_i, node_j):
    for j in node_j:
        for i in node_i:
            if(not first_subset_second(i,j)):
                if(intersection(j, i)):
                    return True
    return False

def is_ip1_subnet_of_ip2(a, b):
   """
   Returns boolean: is `a` subnet of `b`?
   """
   a = ipaddr.IPNetwork(a)
   b = ipaddr.IPNetwork(b)
   a_len = a.prefixlen
   b_len = b.prefixlen
   return a_len >= b_len and a.supernet(a_len - b_len) == b

"""if first is subset of second return True otherwise return False"""
def first_subset_second(first, second):
    dependence = True
    for index in range(0, 4):
        if (str(second[index]) is not "*"):
            if (not (str(second[index]).__eq__(str(first[index])))):
                if (str(second[index]).__contains__("tcp_dst") or str(second[index]).__contains__("tcp_src") or str(first[index]).__eq__("*")):
                    dependence = False
                    break
                elif (not is_ip1_subnet_of_ip2(str(first[index]).split("=")[1] , str(second[index]).split("=")[1])):
                        dependence = False
                        break
    return dependence

def intersection(first, second):
    intersection = True
    for index in range(0, 3):
        if (not ((str(second[index]).__eq__("*")) or (str(first[index]).__eq__("*")))):
            if (not (str(second[index]).__eq__(str(first[index])))):
                if (str(second[index]).__contains__("tcp_dst") or str(second[index]).__contains__("tcp_src")):
                    intersection = False
                    break

                elif (not (is_ip1_subnet_of_ip2(str(first[index]).split("=")[1] , str(second[index]).split("=")[1]) or
                    is_ip1_subnet_of_ip2(str(second[index]).split("=")[1], str(first[index]).split("=")[1]))):
                    intersection = False
                    break
    return intersection
