#!/usr/bin/env python
# coding: utf-8

# In[2]:


from scapy.all import *


# In[9]:


packets = rdpcap('./Tello_接続から離陸まで.pcap')
packets_a = rdpcap('./a.pcap')


# In[4]:


# list_packets_src_ipad = []
# for i, packet in enumerate(packets, 1):
#     if (packet.src == '192.168.10.2') and (packet.dst == '192.168.10.1'):
#         print(len(packet))
#         print(ls(packet))
#         list_packets_src_ipad.append(packet)
# #         send(packet)


# In[30]:


for i, packet in enumerate(packets, 1):
    print(packet[Ether].show)


# In[5]:


# for i, pakcet in enumerate(list_packets_src_ipad, 1):
#     if i % 50 == 0:
#         print('%d / %d' % (i, len(list_packets_src_ipad)))
#     send(pakcet, iface='en0')
# print('finish!')


# In[6]:


# lsc()


# In[ ]:




