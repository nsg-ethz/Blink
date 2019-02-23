from _murmur3 import murmur3
from _murmur3str import murmur3str

import socket

res_dic = {}

tmp = socket.htons(10000)
print murmur3(tmp, 2, 2)%25

print murmur3str('salut', 10, 1)%20
print murmur3str('salutwef', 10, 1)%20
print murmur3str('asac', 10, 1)%20
print murmur3str('cscafewgerg', 10, 1)%20
print murmur3str('ascascasc', 10, 1)%20
print murmur3str('cascassacacsa', 10, 1)%20
print murmur3str('acsascascacsacas', 10, 1)%20
print murmur3str('ergaefef', 10, 1)%20

#with open('flows_list.txt', 'r') as fd:
#    for line in fd.readlines():
#        linetab = line.rstrip('\n').split('\t')

#        ip_src = linetab[0]
#        ip_dst = linetab[1]
#        port_src = linetab[2]
#        port_dst = linetab[3]

#        key = ip_src+ip_dst+port_src+port_dst

#        for i in range(0, 1):
#            hash_tmp = murmur3(key, 100, i+1)

#            print len(hash_tmp)

#            if hash_tmp not in res_dic:
#                res_dic[hash_tmp] = 0
#            res_dic[hash_tmp] += 1

#print res_dic
