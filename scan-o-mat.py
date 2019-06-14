#!/usr/bin/python3

# Thanks to https://gist.github.com/chidea/ for a lot of inspiration and error handling

__author__ = "Jan Goebel"
__email__ = "jan-go@gmx.de"

import sys
import netaddr
import asyncore
import socket
import random
import struct
import time

class Ping(asyncore.dispatcher):
    def __init__(self, ipr, timeout=0.5):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
        self.ipr = ipr
        self.timeout = timeout
        self.packet_size = 56
        self.packet_id = int((id(timeout) * random.random()) % 65535)
        self.packet = self.create_packet(self.packet_id)
        self.time_sent = 0
        self.time_recv = 0
        self.addr = None

    def get_host(self):
        return self.ipr

    def get_result(self):
        """
        return ping results and time spent
        """
        if self.addr:
            return self.addr[0], self.time_recv-self.time_sent
        return None, None

    def create_socket(self, family, type, proto):
        """
        overwrite original create_socket function to include protocol
        """
        sock = socket.socket(family, type, proto)
        sock.setblocking(0)
        self.set_socket(sock)
        self.family_and_type = family, type

    def checksum(self, msg):
        """
        calculate ICMP checksum
        source: http://www.bitforestinfo.com/2018/01/code-icmp-raw-packet-in-python.html
        """
        s = 0       # Binary Sum
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            a = msg[i]
            b = msg[i+1]
            s = s + (a+(b << 8))
        # One's Complement
        s = s + (s >> 16)
        s = ~s & 0xffff
        return s

    def create_payload(self):
        padBytes = []
        startVal = 0x42
        for i in range(startVal, startVal + (self.packet_size)):
            padBytes += [(i & 0xff)]
        data = bytes(padBytes)
        return data

    def create_packet(self, pid):
        """
        create ping packet
        """
        ICMP_ECHO_REQUEST = 8
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, pid, 1)
        data = self.create_payload()
        # include checksum in packet
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, socket.htons(self.checksum(header+data)), pid, 1)
        return header+data

    def handle_connect(self):
        pass

    def handle_accept(self):
        pass

    def handle_close(self):
        self.close()

    def handle_read(self):
        data, addr = self.socket.recvfrom(1024)
        header = data[20:28]
        type_, code, checksum, p_id, sequence = struct.unpack("!BBHHH", header)
        if p_id == self.packet_id:
            self.time_recv = time.time()
            self.addr = addr
            self.close()

    def writable(self):
        return (len(self.packet) > 0)

    def readable(self):
        if (not self.writable()and self.timeout < (time.time() - self.time_sent)):
            self.close()
            return False
        return not self.writable()

    def handle_write(self):
        self.time_sent = time.time()
        while self.packet:
            sent = self.socket.sendto(self.packet, (self.ipr, 1))
            self.packet = self.packet[sent:]

if __name__ == '__main__':
    # get input network or ip address to scan
    value = sys.argv[1]
    net = False
    if value.count('/')>0:
        net = netaddr.IPNetwork(value)
    else:
        net = [netaddr.IPAddress(value)]

    # perform icmp ping sweep to get alive hosts
    # max select sockets 512 possible
    part_size = 512
    start = 0
    end = 512
    start_time = time.time()
    try:
        counter = int(net.num_addresses)
    except:
        counter = len(net)
    while counter>0:
        socket_list = []
        for ipr in net[start:end]:
            socket_list.append(Ping(str(ipr)))
            counter -= 1
        asyncore.loop(timeout=1)
        for sock in socket_list:
            target, rsptime = sock.get_result()
            if target:
                print("%s -> response: %s" % (target, rsptime))
        del socket_list
        start += part_size
        end += part_size
    stop_time = time.time()
    print(stop_time-start_time)
