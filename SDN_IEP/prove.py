from collections import OrderedDict
from random import randint

print "##################################################################"
def get_annunci(numero_annunci_richiesti):
    i = 0
    list_annunci = []
    while  i < numero_annunci_richiesti:
        i = i + 1
        number1 = str(randint(2, 255))
        number2 = str(randint(0, 255))
        number3 = str(randint(0, 255))
        number4 = str(randint(0, 255))
        mask = str(randint(8, 32))
        list_annunci.append(number1 + "." + number2 + "." + number3 + "." + number4 + "/" + mask)
    return list_annunci


annunci_to_do = "["
annunci = get_annunci(5000)
annunci.pop(0)
for annuncio in annunci:
    annunci_to_do = annunci_to_do+"{"+'"'+"prefix"+'"'+":"+'"'+annuncio+'"'+"}"+","
annunci_to_do = annunci_to_do+"{"+'"'+"prefix"+'"'+":"+'"'+"1.0.0.0/24"+'"'+"}"+","
annunci_to_do = annunci_to_do[:-1]+"]"
print annunci_to_do
print "##################################################################"


def get_policy(numero_policy):
    i = 0
    list_policies = []
    while i < numero_policy:
        i =  i + 1
        tcp_src = str(randint(0, 65535))
        tcp_dst = str(80)
        K = True
        while K:
            if tcp_src.__eq__("21"):
                tcp_src = str(randint(0, 65535))
            else:
                K = False

        n1 = str(randint(0, 255))
        n2 = str(randint(0, 255))
        n3 = str(randint(0, 255))
        n4 = str(randint(0, 255))
        ipv4_src = n1 + "." + n2 + "." + n3 + "." + n4
        K = True
        while K:
            if ipv4_src.__eq__("2.0.0.2"):
                n1 = str(randint(0, 255))
                n2 = str(randint(0, 255))
                n3 = str(randint(0, 255))
                n4 = str(randint(0, 255))
                ipv4_src = n1 + "." + n2 + "." + n3 + "." + n4
            else:
                K = False


        n1 = str(randint(0, 255))
        n2 = str(randint(0, 255))
        n3 = str(randint(0, 255))
        n4 = str(randint(0, 255))
        ipv4_dst = n1 + "." + n2 + "." + n3 + "." + n4
        K = True
        while K:
            if ipv4_dst.__eq__("1.0.0.2"):
                n1 = str(randint(0, 255))
                n2 = str(randint(0, 255))
                n3 = str(randint(0, 255))
                n4 = str(randint(0, 255))
                ipv4_dst = n1 + "." + n2 + "." + n3 + "." + n4
            else:
                K = False

        random_num = randint(1, 15)
        #print random_num
        operazione = ""
        if random_num == 1:
            operazione = "{"+'"'+"policy"+'"'+":"+"{"+'"'+"condition"+'"'+": ["+'"'+"AND"+'"'+"," +'"'+"tcp_dst="+tcp_dst+'"'+","+ \
                         '"'+"tcp_src="+tcp_src+'"'+"],"+'"'+"action"+'"'+": ["+'"'+"AS20"+'"'+"]}},"
        elif random_num == 2:
            operazione = "{"+'"'+"policy"+'"'+":"+"{"+'"'+"condition"+'"'+": ["+'"'+"AND"+'"'+"," +'"'+"tcp_dst="+tcp_dst+'"'+","+ \
                         '"'+"ipv4_src="+ipv4_src+'"'+"],"+'"'+"action"+'"'+": ["+'"'+"AS20"+'"'+"]}},"
        elif random_num == 3:
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "AND" + '"' + "," + \
                         '"' + "ipv4_src="+ipv4_src + '"' + "," + '"' + "tcp_src=" + tcp_src + '"' + "]," + '"' + "action" + \
                         '"' + ": [" + '"' + "AS20" + '"'+","+'"' + "AS20" + '"' + "]}},"
        elif random_num == 4:
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "AND" + '"' + "," + \
                         '"' + "tcp_dst=" + tcp_dst + '"' + "," + '"' + "ipv4_dst=" + ipv4_dst + '"' + "]," + '"' + "action" + \
                         '"' + ": [" + '"' + "AS20" + '"' + "]}},"
        elif random_num == 5:
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "AND" + '"' + "," + \
                         '"' + "tcp_src=" + tcp_src + '"' + "," + '"' + "ipv4_dst=" + ipv4_dst + '"' + "]," + '"' + "action" + \
                         '"' + ": [" + '"' + "AS20" + '"'+","+'"' + "AS20" + '"' +","+'"' + "AS20" + '"' + "]}},"
        elif random_num == 6:
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "AND" + '"' + "," + \
                         '"' + "ipv4_src=" + ipv4_src + '"' + "," + '"' + "ipv4_dst=" + ipv4_dst + '"' + "]," + '"' + "action" + \
                         '"' + ": [" + '"' + "AS20" + '"' + "]}},"
        elif random_num == 7:
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "OR" + '"' + "," + \
                         "[" + '"' + "AND" + '"' + ","+'"' + "tcp_dst=" + tcp_dst + '"' + "," + '"' + "tcp_src=" + tcp_src + '"' + "],"+ \
                         '"' + "ipv4_src=" + ipv4_src + '"' + "],"+ '"' + "action" +'"' + ": [" + '"' + "AS20" + '"'+","+'"' + "AS20" + '"'+","+'"' + "AS20" + '"' + "]}},"
        elif random_num == 8:
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "OR" + '"' + "," + \
                         "[" + '"' + "AND" + '"' + "," + '"' + "tcp_dst=" + tcp_dst + '"' + "," + '"' + "ipv4_src=" + ipv4_src + '"' + "]," + \
                         '"' + "tcp_src=" + tcp_src + '"' + "]," + '"' + "action" + '"' + ": [" + '"' + "AS20" + '"'+","+'"' + "AS20" + '"'+","+'"' + "AS20" + '"' + "]}},"
        elif random_num == 9:
            tcp_dst = str(123)
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "OR" + '"' + "," + \
                         "[" + '"' + "AND" + '"' + "," + '"' + "ipv4_src=" + ipv4_src + '"' + "," + '"' + "tcp_src=" + tcp_src + '"' + "]," + \
                         '"' + "tcp_dst=" + tcp_dst + '"' + "]," + '"' + "action" + '"' + ": [" + '"' + "AS20" + '"' + "]}},"
        elif random_num == 10:
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "OR" + '"' + "," + \
                         "[" + '"' + "AND" + '"' + ","+'"' + "tcp_dst=" + tcp_dst + '"' + "," + '"' + "ipv4_dst=" + ipv4_dst + '"' + "],"+ \
                         '"' + "tcp_src=" + tcp_src + '"' + "],"+ '"' + "action" +'"' + ": [" + '"' + "AS20" + '"'+","+'"' + "AS20" + '"' + "]}},"
        elif random_num == 11:
            tcp_dst = str(123)
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "OR" + '"' + "," + \
                         "[" + '"' + "AND" + '"' + ","+'"' + "tcp_src=" + tcp_src + '"' + "," + '"' + "ipv4_dst=" + ipv4_dst + '"' + "],"+ \
                         '"' + "tcp_dst=" + tcp_dst + '"' + "],"+ '"' + "action" +'"' + ": [" + '"' + "AS20" + '"' + "]}},"
        elif random_num == 12:
            tcp_dst = str(123)
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "OR" + '"' + "," + \
                         "[" + '"' + "AND" + '"' + ","+'"' + "ipv4_src=" + ipv4_src + '"' + "," + '"' + "ipv4_dst=" + ipv4_dst + '"' + "],"+ \
                         '"' + "tcp_dst=" + tcp_dst + '"' + "],"+ '"' + "action" +'"' + ": [" + '"' + "AS20" + '"' + "]}},"
        elif random_num == 13:
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "OR" + '"' + "," + \
                         "[" + '"' + "AND" + '"' + ","+'"' + "ipv4_src=" + ipv4_src + '"' + "," + '"' + "ipv4_dst=" + ipv4_dst + '"' + "],"+ \
                         '"' + "tcp_src=" + tcp_src + '"' + "],"+ '"' + "action" +'"' + ": [" + '"' + "AS20" + '"'+","+'"' + "AS20" + '"' + "]}},"
        elif random_num == 14:
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "OR" + '"' + "," + \
                         "[" + '"' + "AND" + '"' + ","+'"' + "tcp_src=" + tcp_src + '"' + "," + '"' + "tcp_dst=" + tcp_dst + '"' + "],"+ \
                         '"' + "ipv4_dst=" + ipv4_dst + '"' + "],"+ '"' + "action" +'"' + ": [" + '"' + "AS20" + '"' + "]}},"
        elif random_num == 15:
            operazione = "{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ": [" + '"' + "OR" + '"' + "," + \
                         "[" + '"' + "AND" + '"' + ","+'"' + "tcp_dst=" + tcp_dst + '"' + "," + '"' + "ipv4_dst=" + ipv4_dst + '"' + "],"+ \
                         '"' + "ipv4_src=" + ipv4_src + '"' + "],"+ '"' + "action" +'"' + ": [" + '"' + "AS20" + '"'+","+'"' + "AS20" + '"' + "]}},"
        list_policies.append(operazione)
    return list_policies



policies = get_policy(100)
policies.pop(0)
policies.append("{" + '"' + "policy" + '"' + ":" + "{" + '"' + "condition" + '"' + ":"  '"' + "tcp_dst=80" + '"'+"," +
                '"' + "action" + '"' + ": [" + '"' + "AS20" + '"' + "]}},")
policies_to_write = ""
for policy in policies:
    policies_to_write = policies_to_write+policy
policies_to_write = policies_to_write[:-1]
policies_to_write="["+policies_to_write+"]"
print policies_to_write