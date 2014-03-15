import socket
import struct
import binascii


src_ip=""
dest_ip=""
src_mac=""
dest_mac=""

def macprint(s):
        #print s
        i=0
        mac=""
        for x in s:
                if i%2==0 and i!=0:
                        mac=mac+":"
                        mac=mac+x
                else:
                        mac=mac+x
                i=i+1

        return mac


def process_etherHeader(eth):
        #print "Processing Ethernet Header"

        global src_mac
        global dest_mac
        eth_hdr=struct.unpack("!6s6s2s",eth)

        dest_mac = binascii.hexlify(eth_hdr[1])
        src_mac = binascii.hexlify(eth_hdr[0])
        eth_type = binascii.hexlify(eth_hdr[2])


        #print "Source Mac Address "+macprint(src_mac)
        #print "Destination Mac Address "+macprint(dest_mac)
        #print "Ethernet Type:"+eth_type
        #print "\n"

def process_ipHeader(ip):
        #print "Processing IP Header"

        global src_ip
        global dest_ip
        ip_hdr=struct.unpack("!8s1s1s2s4s4s",ip)

        time_to_live = binascii.hexlify(ip_hdr[1])
        protocol = binascii.hexlify(ip_hdr[2])
        checksum = binascii.hexlify(ip_hdr[3])
        src_ip = socket.inet_ntoa(ip_hdr[4])
        dest_ip = socket.inet_ntoa(ip_hdr[5])

        #print "Time to Live "+time_to_live
        #print "Protocol "+protocol
        #print "Checksum "+checksum
        #print "Source IP "+src_ip
        #print "Destionation IP "+dest_ip
        #print "\n"

def print_info():
                if src_ip == "192.168.247.1":
                        return
                else:
                        print "    Source MAC           Source IP        Destination MAC      Destination IP"
                        print macprint(src_mac)+"      "+src_ip+"    "+macprint(dest_mac)+"    "+dest_ip

#PF_Packet is basically used for working with low level protocols which is below IP protocol.
#AF_INET basically uses UDP or TCP proctocols
sock=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
#Replace socket.htons(0x0800) using socket.IPPROTO_IP when it is used in Windows Platform
sock.bind(("eth0",0x800))
pkt=sock.recvfrom(4096)


eth = pkt[0][0:14]
process_etherHeader(eth)


ip=pkt[0][14:34]
process_ipHeader(ip)
while True:
        print_info()
