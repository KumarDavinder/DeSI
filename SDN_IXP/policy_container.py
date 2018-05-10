from binary_tree import *
from graph_dependence import *

"""return ogni elemento della lista e' una lista composta da due elementi ex: 
dport=80andsport=21andsIP=1/8 , [u'ASB', u'ASD']"""

def load(inputFile):
    list_rule_action = from_json_to_binary_tree_action(inputFile)
    for tree_action in list_rule_action:
        condition = str(from_binary_tree_only_and_operations(tree_action[0], "", "", "")).replace("  ", " ")
        if (condition[-1:].__eq__(' ')):
            condition = condition[:-1]
        tree_action[0] = condition
    return list_rule_action

def get_great_value_ip(list_IP):
    if (list_IP.__len__() == 0):
        return ""
    if (list_IP.__len__() == 1):
        return list_IP[0]+"_and_"
    else:
        for i in range(0, list_IP.__len__()):
            greater = True
            for j in range(0, list_IP.__len__()):
                if(i is not j):
                    if (not is_ip1_subnet_of_ip2(str(list_IP[j]).split("=")[1] , str((list_IP[i])).split("=")[1])):
                        greater = False
                        break
            if(greater):
                return list_IP[i]+"_and_"
        return ""

def check_correctness_and_operations(list_rule_action):
    for rule_action in list_rule_action:
        rule_only_and = rule_action[0]
        list_sub_rule = rule_only_and.split(" ")
        new_rule = ""
        for rule in list_sub_rule:
            match_list = set(rule.split("_and_"))
            count_dport = 0
            count_sport = 0
            list_sIP = []
            list_dIP = []
            stop = True
            new_sub_rule = ""
            if match_list.__len__() > 1:
                for element in match_list:
                    element = str(element)
                    if (not(element.__contains__("ipv4_src=") or element.__contains__("ipv4_dst="))):
                        new_sub_rule += element + "_and_"
                    if (element.__contains__("ipv4_src=")):
                        list_sIP.append(element)
                    elif (element.__contains__("ipv4_dst=")):
                        list_dIP.append(element)
                    elif (element.__contains__("tcp_dst=")):
                        count_dport = count_dport + 1
                    elif (element.__contains__("tcp_src=")):
                        count_sport = count_sport + 1
                    if (count_dport >= 2 or count_sport >= 2):
                        stop = False
                        break
                if stop:
                    new_sub_rule += get_great_value_ip(list_sIP)
                    new_sub_rule += get_great_value_ip(list_dIP)
                    if(not new_sub_rule.__eq__("")):
                        new_rule += new_sub_rule[:new_sub_rule.__len__() - 5] + " "
            else:
                new_rule += str(next(iter(match_list)))+" "
        new_rule = new_rule[:-1]
        if new_rule.__eq__(""):
            list_rule_action.remove(rule_action)
        else:
            rule_action[0] = new_rule
    return list_rule_action

def check_j_subset_i_to_cover(quadruples_second, quadruples_first):
    for i in quadruples_first:
        boolean = True
        for j in quadruples_second:
            if (not first_subset_second(j, i)):
                boolean = False
        if boolean:
            return True
    return False

def get_dict_covers(list_rule_action):
    cover_dictionary = {}
    for index in range(0, list_rule_action.__len__()):
        cover_dictionary.update({index: []})
    for i in range(0, list_rule_action.__len__()-1):
        action_first = list_rule_action[i][1]
        for j in range(i+1, list_rule_action.__len__()):
            action_second = list_rule_action[j][1]
            action_equal = True
            if (action_first.__len__() == action_second.__len__()):
                for first in action_first:
                    boolean = False
                    for second in action_second:
                        if (first.__eq__(second)):
                            boolean = True
                            break
                    if (boolean == False):
                        action_equal = False
                        break
            else:
                action_equal = False
            if (action_equal):
                quadruples_first = get_quadruples(list_rule_action[i][0])
                quadruples_second = get_quadruples(list_rule_action[j][0])
                if (check_j_subset_i_to_cover(quadruples_second, quadruples_first)):
                    cover_dictionary.get(i).append(j)
    return cover_dictionary

def get_list_rule_action(inputFileJson):
    list_rule_action = load(inputFileJson)
    print "prima"
    for index in range(0,list_rule_action.__len__()):
        print str(list_rule_action[index][0])+" --> "+str(list_rule_action[index][1])
    list_rule_action = check_correctness_and_operations(list_rule_action)
    print "dopo"
    for index in range(0, list_rule_action.__len__()):
        print str(list_rule_action[index][0]) + " --> " + str(list_rule_action[index][1])
    print

    return list_rule_action

def get_dict_graph_dependence(list_rule_action):
    return get_dictionary_of_graph_dependence(list_rule_action)

