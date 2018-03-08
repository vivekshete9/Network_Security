# Program to build a mini firewall using python
import threading
from threading import Thread
import struct
import sys
import time
import socket
from socket import AF_INET, AF_INET6, inet_ntoa
import nfqueue
from scapy.all import send, IP, TCP

# from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from math import ceil
import os
import re
import binascii
from Tkinter import *  #for gui directory

global inputprotocol, inputportnum, inputipaddr, blkip, blkport, blkproto, enblk  # root action,, actiontype


class Firewall:
    def __init__(self):
        self.protocolname = ''
        self.srcipaddress = ''
        self.srcportnum = 0

        # """ Checks the packet to make sure the IPv4 address is valid. Upon
        # verifying that the addresses in the IP packet are valid, method
        # returns True. Else, it returns False. """

    def valid_IP_address(self, ext_addr):
        try:
            socket.inet_ntoa(ext_addr)
            return True
        except socket.error:
            return False

    def obtain_fields(self, pckt):
        try:
            protocol = struct.unpack('!B', pckt[9:10])          # (integer,)
            total_length = struct.unpack('!H', pckt[2:4])
            return self.strip_format(protocol), self.strip_format(total_length)
        except struct.error as e:
            print e
            return None, None

    def valid_ip_header(self, pckt):
        try:
            # print pckt
            ip_header = struct.unpack('!B', pckt[0:1])
            return self.strip_format(ip_header)
        except struct.error as e:
            print e
            print pckt[0:1]
            return None

    def get_udp_length(self, pckt, startIndex):
        try:
            length = struct.unpack('!H', pckt[startIndex + 4: startIndex + 6])
            return self.strip_format(length)
        except struct.error:
            return None

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pckt_dir, pckt):
        ip_header = self.valid_ip_header(pckt)
        if (ip_header == None):
            print 1
            return
        ip_header = ip_header & 0x0f
        if (ip_header < 5):
            print 2
            return

        protocol, total_length = self.obtain_fields(pckt)
        if (protocol == None and total_length == None):
            print 3
            return

        if (total_length != len(pckt)):
            print 4
            return

        if (self.protocol_selector(protocol) == None):
            # self.send_packet(pckt, pckt_dir)
            print 5
            return

        src_addr, dst_addr, pckt_dir = pckt[12:16], pckt[16:20], self.packet_direction(pckt_dir)
        if (pckt_dir == 'incoming'):
            external_addr = src_addr
        else:
            external_addr = dst_addr
        if not (self.valid_IP_address(external_addr)):  # check valid address.
            print 6
            return

        if (protocol == 6):  # TCP
            if (pckt_dir == 'incoming'):
                external_port = self.handle_external_port(pckt, (ip_header) * 4)
            else:
                external_port = self.handle_external_port(pckt, ((ip_header) * 4) + 2)
            if (external_port == None):  # drop packet due to port socket error.
                print 7
                return

        elif (protocol == 1):  # ICMP
            type_field = self.handle_icmp_packet(pckt, (ip_header * 4))
            if (type_field == None):
                print 8
                return

        elif (protocol == 17):  # UDP
            udp_length = self.get_udp_length(pckt, (ip_header * 4))
            if (udp_length == None or udp_length < 8):
                print 9
                return
            if (pckt_dir == 'incoming'):
                external_port = self.handle_external_port(pckt, (ip_header) * 4)
                if (external_port == None):
                    print 10
                    return

        verdict = "pass"
        self.protocolname = self.protocol_selector(protocol)
        self.srcipaddress = external_addr
        if (protocol != 1):
            self.srcportnum = external_port

    """ Protocol Selector."""

    def protocol_selector(self, protocol):
        if (protocol == 1):
            return "icmp"
        elif (protocol == 6):
            return 'tcp'
        elif (protocol == 17):
            return 'udp'
        return None

    """ Returns True if the protocol of the packet is either TCP, UDP, or ICMP.
        Else, the method returns False. """

    def check_protocol(self, protocol):
        return (protocol == 'tcp') or (protocol == 'udp') or (protocol == 'icmp')

    """ Returns True if the external IP address is within the range of the
        IP prefix."""

    def within_range(self, start_port, end_port, external_ip):
        return external_ip >= start_port and external_ip <= end_port

    """ Check if the data is an IP prefix."""

    def is_IP_Prefix(self, data):
        return data.find('/')

    """ Strips the parentheses and comma off the number and converts string to int."""

    def strip_format(self, format_str):
        new_str = str(format_str)
        return int(new_str[1: len(new_str) - 2])

    """ Returns the external port and checks to see if there is a socket error. If
        the port is valid, then it returns a number, else it returns 'None'. """

    def handle_external_port(self, pckt, startIndex):
        try:
            ext_port = pckt[startIndex: startIndex + 2]
            ext_port = struct.unpack('!H', ext_port)
            return ext_port
        except struct.error:
            return None

    """ Returns the TYPE field for the IMCP packet."""

    def handle_icmp_packet(self, pckt, startIndex):
        try:
            type_field = pckt[startIndex: startIndex + 1]
            type_field = struct.unpack('!B', type_field)
            return self.strip_format(type_field)
        except struct.error:
            return None

    """ Returns the direction of the packet in a string."""

    def packet_direction(self, direction):
        if (direction == 'outgoing'):
            return 'outgoing'
        else:
            return 'incoming'


# def cb(i, payload):

def cb(i, payload):         #Decision Making on whether to accept or drop packet depending on Port#/ Protocol text Entry/ IP address check-button status of GUI
    data = payload.get_data()
    pkt = IP(data)

    f = Firewall()
    f.handle_packet("incoming", str(pkt))
    print f.protocolname
    print socket.inet_ntoa(f.srcipaddress)
    print f.srcportnum
    
#TO ppt
    if enblk == 1:
        if blkproto == True:
            if inputprotocol == f.protocolname:  # TCP, UDP, ICMP
                payload.set_verdict(nfqueue.NF_DROP)
                print f.protocolname + " Packet blocked"
	elif blkproto == False:
	    payload.set_verdict(nfqueue.NF_ACCEPT)
            print f.protocolname + " Packet Unblocked"

        if blkip == True:
            if inputipaddr == socket.inet_ntoa(f.srcipaddress):  # IP address
                payload.set_verdict(nfqueue.NF_DROP)
                print socket.inet_ntoa(f.srcipaddress) + " blocked"
        elif blkip == False:
	    payload.set_verdict(nfqueue.NF_ACCEPT)
            print socket.inet_ntoa(f.srcipaddress) + " Packet Unblocked"

        if blkport == True:
            if int(inputportnum) in f.srcportnum:
                payload.set_verdict(nfqueue.NF_DROP)
                print inputportnum + " blocked"
        elif blkport == False:
	    payload.set_verdict(nfqueue.NF_ACCEPT)
            print inputportnum + " Packet Unblocked"
    else:
        payload.set_verdict(nfqueue.NF_ACCEPT)
        print "Packet accepted"
#<-PPT

    #else:
        #payload.set_verdict(nfqueue.NF_ACCEPT)
        #print "Packet accepted"

    '''
    LabelURL2 = Label(BF, text= "URL to Block: ",pady =20, padx = 10 )      # URL
    URLentry = Entry(BF,command = setURLtoblock)
    URLbutton3 = Button(BF, text = "Done!", fg = 'BLUE', bg = 'YELLOW', command = setURLtoblock)
    LabelURL2.grid(row = 3, column = 0)
    URLentry.grid(row = 3, column =1)
    URLbutton3.grid(row = 3, column =2)
    '''


    #############################################################################################################################


    # def blockURL()


def main():         
    global inputprotocol, inputportnum, inputipaddr, blockip, blockport, blockproto, enblock 
    iptablesr = "sudo iptables -A INPUT -j NFQUEUE --queue-num 0"

    print("Iptables rule implemented")
    print(iptablesr)
    os.system(iptablesr)

    def callback():     #Extract values of port#, IP address, Protocol entry and another controls from GUI in callback() and use the same values in cb for decision making(nfqueue(set_verdict)


        global root
        root = Tk()

        def setIPtoblock():
            inputipaddr = IPentry.get()
            print('IP address to block: ' + inputipaddr)
            return inputipaddr

        def setPorttoblock():
            inputportnum = Portentry.get()
            print('Port Number to block' + inputportnum)
            return inputportnum

        def setPrototoblock():
            inputprotocol = Protoentry.get()
            print('Protocol to block' + inputprotocol)
            return inputprotocol

        def blockIP():
            i = var1.get()
            if i is 1:
                blockip = True
                print ('Command : Block IP ADDRESS')
                return blockip


            elif i is 0:
                blockip = False
                print ('Command : Unblock IP ADDRESS')
                return blockip

        def blockPort():
            i = var2.get()
            if i is 1:
                blockport = True
                print ('Command : Block PORT')
                return blockport

            elif i is 0:
                blockport = False
                print ('Command : Unblock PORT')
                return blockport

        def blockProto():
            i = var3.get()
            if i is 1:
                if inputprotocol == f.protocolname:  # TCP, UDP, ICMP
                    blockproto = True
                    print ('Command : Block PROTOCOL')
                    return blockproto


            elif i is 0:
                blockproto = False
                print ('Command : Unblock PROTOCOL')
                return blockproto

	def exit(event):
	    root.quit()

        def EnableBlock():
            i = enblock.get()
            return i

        root.title('FIREWALL')
        TF = Frame(root)  # Top Frame
        TF.grid(sticky=N)
        Heading = Label(TF, text='Welcome to Firewall App')
        Heading.grid(row=0, sticky=N, column=2)
        global var1, var2, var3, var4
        var1 = IntVar()
        var2 = IntVar()
        var3 = IntVar()
        var4 = IntVar()
        enblock = IntVar()
        IPbutton1 = Radiobutton(TF, text="BLOCK", variable=var1, value=1, fg='red', pady=20, padx=10,
                                command=blockIP)  # IP ADDRESS
        IPbutton1.grid(row=1, column=0)
        IPbutton2 = Radiobutton(TF, text="UNBLOCK", variable=var1, value=0, fg='green', pady=20, padx=10,
                                command=blockIP)
        IPbutton2.grid(row=1, column=2) 

        IPLabel1 = Label(TF, text="IP Address")
        IPLabel1.grid(row=1, column=3)

        Portbutton1 = Radiobutton(TF, text="BLOCK", variable=var2, value=1, fg='red', pady=20, padx=10,
                                  command=blockPort)  # PORT NUMBER
        Portbutton1.grid(row=2, column=0)  

        Portbutton2 = Radiobutton(TF, text="UNBLOCK", variable=var2, value=0, fg='green', pady=20, padx=10,
                                  command=blockPort)
        Portbutton2.grid(row=2, column=2)  

        PortLabel1 = Label(TF, text="Port Number")
        PortLabel1.grid(row=2, column=3)

        Protobutton1 = Radiobutton(TF, text="BLOCK", variable=var3, value=1, fg='red', pady=20, padx=10,
                                   command=blockProto)  # PROTOCOL
        Protobutton1.grid(row=3, column=0) 

        Protobutton2 = Radiobutton(TF, text="UNBLOCK", variable=var3, value=0, fg='green', pady=20, padx=10,
                                   command=blockProto)
        Protobutton2.grid(row=3, column=2) 

        ProtoLabel1 = Label(TF, text="Protocol")
        ProtoLabel1.grid(row=3, column=3)

        Enable = Checkbutton(TF, text="Enable BLOCK", variable=enblock, command=EnableBlock, onvalue=1, offvalue=0,
                             height=5, width=20)
        Enable.grid(row=4, column=2)

     
        

        BF = Frame(root)  # Bottom Frame
        BF.grid(sticky=S)

        LabelIP2 = Label(BF, text="IP Address to Block: ", pady=20, padx=10)  # IP ADDRESS
        IPentry = Entry(BF)
        IPbutton3 = Button(BF, text="Done!", fg='BLUE', bg='YELLOW', command=setIPtoblock)
        LabelIP2.grid(row=0, column=0)
        IPentry.grid(row=0, column=1)
        IPbutton3.grid(row=0, column=2)

        LabelPort2 = Label(BF, text="Port to Block: ", pady=20, padx=10)  # PORT NUMBERs
        Portentry = Entry(BF)
        Portbutton3 = Button(BF, text="Done!", fg='BLUE', bg='YELLOW', command=setPorttoblock)
        LabelPort2.grid(row=1, column=0)
        Portentry.grid(row=1, column=1)
        Portbutton3.grid(row=1, column=2)

        LabelProto2 = Label(BF, text="Protocol to Block: ", pady=20, padx=10)  # PROTOCOL
        Protoentry = Entry(BF)
        Protobutton3 = Button(BF, text="Done!", fg='BLUE', bg='YELLOW', command=setPrototoblock)
        LabelProto2.grid(row=2, column=0)
        Protoentry.grid(row=2, column=1)
        Protobutton3.grid(row=2, column=2)
	
	root.bind('<Control-c>',exit)
        root.mainloop()

        setipfunc = ()
        setprotofunc = ()
        setportfunc = ()
        blockipfunc = ()
        blockprotofunc = ()
        blockportfunc = ()
        Enblockfunc = ()

        setipfunc = setIPtoblock()
        setprotofunc = setPrototoblock()
        setportfunc = setPorttoblock()
        blockipfunc = blockIP()
        blockprotofunc =blockPort()
        blockportfunc = blockProto()
        Enblockfunc = EnableBlock()



        print setipfunc
        print setprotofunc
        print setportfunc
        print blockipfunc
        print blockprotofunc
        print blockportfunc
        print Enblockfunc

        if setipfunc[0] != "":
            inputipaddr = setipfunc[0]

        if setprotofunc[0] != "":
            inputprotocol = setprotofunc[0]

        if setportfunc[0] != "":
            inputportnum = setportfunc[0]

        if blockipfunc[0] != None:
            blkip = blockipfunc[0]

        if blockprotofunc[0] != None:
            blkproto = blockprotofunc[0]

        if blockportfunc[0] != None:
            blkport = blockportfunc[0]

        if Enblockfunc[0] != None:
            enblk = Enblockfunc[0]


 #Packet blocking method code (nfqueue)  
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(cb)
    q.create_queue(0)
    def run():    
	try:
            q.try_run()

        except KeyboardInterrupt as e:
            print ("Interrupted")
	    inputipaddr=''
            inputportnum=0
            inputprotocol=''
	    enblock = None
	    blockport = None
	    blockproto = None
	    blockip = None
	    print ("unbind")
            q.unbind(AF_INET)
            print ("close")
            q.close()

    if __name__=='__main__':
	Thread(target = run).start()
        Thread(target = callback).start()

    '''print ("unbind")
    q.unbind(AF_INET)
    print ("close")
    q.close()


    except KeyboardInterrupt, e:
    print ("Interrupted")
    print ("unbind")
    q.unbind(AF_INET)
    print ("close")
    q.close()'''

main()

################################################################################################################################################################################



