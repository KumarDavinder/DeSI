from policy_container import *


print "*************************************************************************************"
list_rule_action = get_list_rule_action('/Users/davinderkumar/Desktop/Json_Policies/input/cover1.json')
print list_rule_action
dictionary_graph_dependence = get_dict_graph_dependence(list_rule_action)
dictionary_cover_set = get_dict_of_cover(list_rule_action)
print "graph dependence map: "+str(dictionary_graph_dependence)
print "cover map: "+str(dictionary_cover_set)
print
print list_rule_action
for index in range(0, list_rule_action.__len__()):
    print str(index)+") "+str(list_rule_action[index][0]) + " --> " + str(list_rule_action[index][1])
print "*************************************************************************************"
