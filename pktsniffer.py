# - *- coding: utf- 8 - *-
import dpkt
from scapy.all import *
import struct
import sys
import codecs
import collections

"""
file: pktsniffer.py
@author: Lyan Ye (yxy6465)
Description: Program that read the pcap file to create a filter tool that is able to
             filter the specific information out. Filter includes: host, port, ip,
             tcp, udp, icmp, net, and, or and not.

Header field helper:
packet header(16): ts(4) ts(4) size(4) size(4)
ethe header(14): destination Mac(6), source mac(6), type(2)
ip: 20bytes with options
udp/tcp/icmp
packets_info=[([eth],[ip],[tup/dup/cimp])]
"""

# global value
ethe_header_len = 14
pkt_header_len = 16


def read_and_store_pcap(file_name):
    """
    The function to read and store the pcap file into the list
    :param file_name: the name of pcap file
    :return: the list that contains ether header, ip header and tcp/udp/icmp header
             for each packet.
    """
    file = open(file_name, "rb")
    global_header = file.read(24).hex()
    byte = file.read(16)
    packets = []
    bytes = []
    sizes = []
    while byte:
        packet_header = byte.hex()
        # parse the size for each packet
        size = struct.unpack("<L", codecs.decode(str(packet_header[16:24]), "hex"))[0]
        sizes.append(size)
        # read the whole packet by its size from the bytes
        byte = file.read(size).hex()
        bytes.append(byte)
        byte = file.read(16)
    for size in sizes:
        packets.append(([size], [], []))
    i = 0

    for pkt in bytes:
        packets = handle_pkt_header(pkt, packets, i)
        packets, start_point = handle_ip_header(pkt, packets, i)
        protocol = packets[i][1][7]
        if protocol == 1:
            packets = handle_icmp(pkt, packets, i, start_point)
        elif protocol == 6:
            packets = handle_tcp(pkt, packets, i, start_point)
        elif protocol == 17:
            packets = handle_udp(pkt, packets, i, start_point)
        i += 1
        # print(packets)
    return packets


def handle_pkt_header(pkt, packets, index):
    """
    To handle and store the ethernet header
    :param pkt: the pkt to be handled
    :param packets: the list of packets that store main information for each packets
    :param index: the index of specific packet
    :return: the updated packets
    """
    dest_mac = pkt[0:12]
    str_dest_mac = dest_mac[0:2]
    for i in range(2, len(dest_mac), 2):
        str_dest_mac += ":" + dest_mac[i:i+2]
    packets[index][0].append(str_dest_mac)
    src_mac = pkt[12:24]
    str_src_mac = pkt[0:2]
    for i in range(2, len(src_mac), 2):
        str_src_mac += ":" + src_mac[i:i+2]
    packets[index][0].append(str_src_mac)
    etherType = pkt[24:28]
    packets[index][0].append(etherType)

    return packets


def handle_ip_header(pkt, packets, index):
    """
    To handle and store the ip header for each packet.
    :param pkt: the packet to be handled
    :param packets: the list of packets is going to be updated
    :param index: the index of specific packet
    :return: the updated packets
    """
    ver = pkt[28]
    ihl = pkt[29]
    type_of_service = pkt[30:32]
    total_length = int(pkt[32:36], 16)
    identification = int(pkt[36:40], 16)
    flags = pkt[40:44]
    ttl = int(pkt[44:46], 16)
    protocol = int(pkt[46:48], 16)
    header_checksum = pkt[48:52]
    src_ip = pkt[52:60]
    dest_ip = pkt[60:68]
    str_src = str(int(src_ip[0:2], 16))
    for i in range(2, len(src_ip), 2):
        str_src += "." + str(int(src_ip[i:i+2], 16))
    str_dest = str(int(dest_ip[0:2], 16))
    for i in range(2, len(dest_ip), 2):
        str_dest += "." + str(int(dest_ip[i:i+2], 16))
    next_start_point = 2 * (ethe_header_len + int(ihl) * 4)
    options = pkt[68:2*(ethe_header_len + int(ihl)*4)]

    # store it to specific location for each packet
    packets[index][1].append(ver)
    packets[index][1].append(ihl)
    packets[index][1].append(type_of_service)
    packets[index][1].append(total_length)
    packets[index][1].append(identification)
    packets[index][1].append(flags)
    packets[index][1].append(ttl)
    packets[index][1].append(protocol)
    packets[index][1].append(header_checksum)
    packets[index][1].append(str_src)
    packets[index][1].append(str_dest)
    packets[index][1].append(options)

    return packets, next_start_point


def handle_icmp(pkt, packets, i, start_point):
    """
    To handle and store the data from icmp header
    :param pkt: the packet to be handled.
    :param packets: the list of packets to be updated
    :param i: the index of the packet
    :param start_point: the start point to read the icmp header
    :return: the updated packet
    """
    icmp_type = int(pkt[start_point:start_point+2], 16)
    start_point = start_point + 2
    icmp_code = int(pkt[start_point:start_point+2], 16)
    start_point = start_point + 2
    icmp_checksum = pkt[start_point:start_point+4]
    packets[i][2].append(icmp_type)
    packets[i][2].append(icmp_code)
    packets[i][2].append(icmp_checksum)
    return packets


def handle_tcp(pkt, packets, i, start_point):
    """
        To handle and store the data from tcp header
        :param pkt: the packet to be handled.
        :param packets: the list of packets to be updated
        :param i: the index of the packet
        :param start_point: the start point to read the tcp header
        :return: the updated packet
        """
    src_port = int(pkt[start_point:start_point+4], 16)
    start_point += 4
    dest_port = int(pkt[start_point:start_point+4], 16)
    start_point += 4
    sequence_num = int(pkt[start_point:start_point+8], 16)
    start_point += 8
    acknowledgment = int(pkt[start_point:start_point+8], 16)
    start_point += 8
    data_offset = int(pkt[start_point], 16) * 4
    start_point += 2
    flags = pkt[start_point:start_point+2]
    flags_str = ""
    for f in flags:
        flags_str += str(format(int(f), '04b'))
    start_point += 2
    window_size = int(pkt[start_point:start_point+4], 16)
    start_point += 4
    checksum_value = pkt[start_point:start_point+4]
    start_point += 4
    urgent_pointer = int(pkt[start_point:start_point+4], 16)
    start_point += 4
    options = int((2 * packets[i][0][0] - start_point)/2)

    packets[i][2].append(src_port)
    packets[i][2].append(dest_port)
    packets[i][2].append(sequence_num)
    packets[i][2].append(acknowledgment)
    packets[i][2].append(data_offset)
    packets[i][2].append(flags_str)
    packets[i][2].append(window_size)
    packets[i][2].append(checksum_value)
    packets[i][2].append(urgent_pointer)
    packets[i][2].append(options)
    return packets


def handle_udp(pkt, packets, i, start_point):
    """
        To handle and store the data from udp header
        :param pkt: the packet to be handled.
        :param packets: the list of packets to be updated
        :param i: the index of the packet
        :param start_point: the start point to read the udp header
        :return: the updated packet
        """
    src_port = int(pkt[start_point:start_point + 4], 16)
    start_point += 4
    dest_port = int(pkt[start_point:start_point + 4], 16)
    start_point += 4
    length = int(pkt[start_point:start_point+4], 16)
    start_point += 4
    checksum_value = pkt[start_point:start_point+4]
    packets[i][2].append(src_port)
    packets[i][2].append(dest_port)
    packets[i][2].append(length)
    packets[i][2].append(checksum_value)

    return packets


def output_generator(pkt):
    """
    To generate the output according to the packet
    :param pkt: the packet to be displayed
    :return:
    """
    ethe_header = pkt[0]
    ip_header = pkt[1]
    protocol = pkt[1][7]
    data_header = pkt[2]
    ethe_prefix = "ETHER: "
    ip_prefix = "IP: "
    tcp_prefix = "TCP: "
    udp_prefix = "UDP: "
    icmp_prefix = "ICMP: "
    # print ether header information
    print("\n" + ethe_prefix + "----- Ether Header -----")
    print(ethe_prefix)
    print(ethe_prefix + "Packet size = " + str(ethe_header[0]) + " bytes")
    print(ethe_prefix + "Destination = " + str(ethe_header[1]))
    print(ethe_prefix + "Source = " + str(ethe_header[2]))
    print(ethe_prefix + "Ethertype = " + str(ethe_header[3]) + " (IP)")
    print(ethe_prefix)

    print(ip_prefix + "----- IP Header -----")
    print(ip_prefix)
    print(ip_prefix + "Version = " + str(ip_header[0]))
    print(ip_prefix + "Header length = " + str(4 * int(ip_header[1])) + " bytes")
    print(ip_prefix + "Type of service = 0x" + str(ip_header[2]))
    if str(ip_header[2]) == "00":
        print(ip_prefix + "\txxx. .... = 0 (precedence)")
        print(ip_prefix + "\t...0 .... = normal delay")
        print(ip_prefix + "\t.... 0... = normal throughput")
        print(ip_prefix + "\t.... .0.. = normal reliability")
    print(ip_prefix + "Total length = " + str(ip_header[3]) + " bytes")
    print(ip_prefix + "Identification = " + str(ip_header[4]))
    print(ip_prefix + "Flags = 0x" + str(ip_header[5]))
    flag = str(format(int(ip_header[5][0]), '04b'))
    if flag[0] == "0":
        print(ip_prefix + "\t0... ... = Reserved bit: Not set")
    else:
        print(ip_prefix + "\t1... ... = Reserved bit: set")
    if flag[1] == "0":
        print(ip_prefix + "\t.0.. ... = Don't fragment: Not set")
    else:
        print(ip_prefix + "\t.1.. ... = Don't fragment: set")
    if flag[2] == "0":
        print(ip_prefix + "\t..0. ... = More fragments: Not set")
    else:
        print(ip_prefix + "\t..1. ... = More fragments: set")
    flag_offset = str((int(ip_header[5][2:3])))
    print(ip_prefix + "Fragment offset = " + flag_offset + " bytes")
    print(ip_prefix + "Time to live = " + str(ip_header[6]) + " seconds/hops")
    if protocol == 1:
        print(ip_prefix + "Protocol = " + str(protocol) + " (ICMP)")
    if protocol == 17:
        print(ip_prefix + "Protocol = " + str(protocol) + " (UDP)")
    if protocol == 6:
        print(ip_prefix + "Protocol = " + str(protocol) + " (TCP)")
    print(ip_prefix + "Header checksum = " + str(ip_header[8]))
    print(ip_prefix + "Source address = " + str(ip_header[9]))
    print(ip_prefix + "Destination address = " + str(ip_header[10]))
    if ip_header[11] == "":
        print(ip_prefix + "No options")
    else:
        print(ip_prefix + "Options: " + ip_header[11])
    print(ip_prefix)

    if protocol == 1:
        print(icmp_prefix + "----- ICMP Header -----")
        print(icmp_prefix)
        if str(data_header[0]) == "8":
            print(icmp_prefix + "Type = " + str(data_header[0]) + " (Echo request)")
        elif str(data_header[0]) == "0":
            print(icmp_prefix + "Type = " + str(data_header[0]) + " (Echo reply)")
        else:
            print(icmp_prefix + "Type = " + str(data_header[0]))
        print(icmp_prefix + "Code = " + str(data_header[1]))
        print(icmp_prefix + "Checksum = " + str(data_header[2]))
        print(icmp_prefix)

    elif protocol == 6:
        print(tcp_prefix + "----- TCP Header -----")
        print(tcp_prefix)
        print(tcp_prefix + "Source port = " + str(data_header[0]))
        print(tcp_prefix + "Destination port = " + str(data_header[1]))
        print(tcp_prefix + "Sequence number = " + str(data_header[2]))
        print(tcp_prefix + "Acknowledgement number = " + str(data_header[3]))
        print(tcp_prefix + "Data offset = " + str(data_header[4]) + " bytes")
        flag = str(data_header[5])
        print(tcp_prefix + "\tReserved: Not set")
        print(tcp_prefix + "\tNonce: Not set")
        if flag[0] == "0":
            print(tcp_prefix + "\tCWR: Not set")
        else:
            print(tcp_prefix + "\tCWR: Set")
        if flag[1] == "0":
            print(tcp_prefix + "\tECN-Echo : No set")
        else:
            print(tcp_prefix + "\tECN-Echo: Set")
        if flag[2] == "0":
            print(tcp_prefix + "\tUrgent: Not set")
        else:
            print(tcp_prefix + "\tUrgent: Set")
        if flag[3] == "0":
            print(tcp_prefix + "\tAcknowledgment: No set")
        else:
            print(tcp_prefix + "\tAcknowledgment: Set")
        if flag[4] == "0":
            print(tcp_prefix + "\tPush: No set")
        else:
            print(tcp_prefix + "\tPush: Set")
        if flag[5] == "0":
            print(tcp_prefix + "\tReset: No set")
        else:
            print(tcp_prefix + "\tReset: Set")
        if flag[6] == "0":
            print(tcp_prefix + "\tSyn: No set")
        else:
            print(tcp_prefix + "\tSyn: Set")
        if flag[7] == "0":
            print(tcp_prefix + "\tFin: No set")
        else:
            print(tcp_prefix + "\tFin: Set")
        print(tcp_prefix + "Window = " + str(data_header[6]))
        print(tcp_prefix + "Checksum 0x= " + str(data_header[7]))
        print(tcp_prefix + "Urgent pointers = " + str(data_header[8]))
        if data_header[9] != 0:
            print(tcp_prefix + "Options")
        else:
            print(tcp_prefix + "No options")
        print(tcp_prefix)

    elif protocol == 17:
        print(udp_prefix + "----- UDP Header -----")
        print(udp_prefix)
        print(udp_prefix + "Source port = " + str(data_header[0]))
        print(udp_prefix + "Destination port = " + str(data_header[1]))
        print(udp_prefix + "Length = " + str(data_header[2]))
        print(udp_prefix + "Checksum = " + str(data_header[3]))
        print(udp_prefix)


def handle_commands(packets, arguments):
    """
    To handle the commands.
    :param packets: the packets to be filtered
    :param arguments: the arguments
    :return:
    """
    # if limit number is -1 meaning no limit
    limit_number = -1
    matched_packets = []

    # handle only -c flag occurs
    if len(arguments) == 2 and arguments[0] == "-c" and isinstance(int(arguments[1]), int):
        limit_number = int(arguments[1])
        for pck in packets:
            while limit_number > 0:
                output_generator(pck)
                limit_number -= 1
        return

    # while loop until the whole arguments is popped
    arg = arguments.popleft()
    while arg:
        # handle and
        if arg == "and":
            if len(arguments) == 0:
                print("Commands should be followed by \"and\" operator.")
                sys.exit()
            else:
                # commands after and
                arg = arguments.popleft()
                new_matched, arg = handle_filter(packets, arg, arguments)

                matched_packets = [x for x in matched_packets if x in new_matched]

        # handle or
        elif arg == "or":
            if len(arguments) == 0:
                print("Commands should be followed by \"or\" operators.")
                sys.exit()
            else:
                arg = arguments.popleft()

                new_matched, arg = handle_filter(packets, arg, arguments)

                matched_packets = [x for x in matched_packets if x not in new_matched] +\
                    [x for x in matched_packets if x in new_matched] +\
                    [x for x in new_matched if x not in matched_packets]
        # handle -c limit flag
        elif arg == "-c":
            if len(arguments) == 0:
                print("\"-c\" flag should be f commands.")
                sys.exit()
            else:
                arg = arguments.popleft()
                limit_number = int(arg)
        # handle other commands
        else:
            matched_packets, arg = handle_filter(packets, arg, arguments)

        if len(arguments) != 0:
            arg = arguments.popleft()
        else:
            # break if arguments is empty
            break
    for pkt in matched_packets:
        # pass the matched packet to the output generator
        if limit_number == -1:
            output_generator(pkt)
        elif limit_number > 0:
            while limit_number > 0:
                output_generator(pkt)
                limit_number -= 1


def handle_filter(packets, arg, arguments):
    """
    To handle different filter flag
    :param packets: the packets to be filtered
    :param arg: the current argument
    :param arguments: the left arguments
    :return: the matched packets list and next argument to be handled
    """
    matched_packets = []
    if arg == "host":
        if len(arguments) == 0:
            print("A host IP address should be followed by the host command.")
            sys.exit()
        else:
            # ip address here
            arg = arguments.popleft()
            for pkt in packets:
                dest_ip = pkt[1][10]
                src_ip = pkt[1][9]
                if arg == dest_ip or arg == src_ip:
                    matched_packets.append(pkt)
    elif arg == "ip":
        for pkt in packets:
            if str(pkt[0][3]) == "0800":
                matched_packets.append(pkt)
    elif arg == "port":
        if len(arguments) == 0:
            print("\"port\" cannot be the last argument.")
            sys.exit()
        else:
            # port number
            arg = arguments.popleft()

            for pkt in packets:
                if pkt[1][7] == 6 or pkt[1][7] == 17:
                    if str(pkt[2][0]) == arg or str(pkt[2][1]) == arg:
                        matched_packets.append(pkt)

    elif arg == "tcp":
        for pkt in packets:
            if pkt[1][7] == 6:
                matched_packets.append(pkt)
    elif arg == "udp":
        for pkt in packets:
            if pkt[1][7] == 17:
                matched_packets.append(pkt)
    elif arg == "icmp":
        for pkt in packets:
            if pkt[1][7] == 1:
                matched_packets.append(pkt)
    elif arg == "net":
        if len(arguments) == 0:
            print("\"net net\" is required. ")
            sys.exit()
        else:
            # ip prefix
            arg = arguments.popleft()
            if len(arg.split(".")) != 4:
                print("Please enter a valid ip address format. (x.x.x.x)")
                sys.exit()
            prefix_length = 0
            length = len(arg)
            if arg == "0.0.0.0":
                prefix_length = 0
            elif arg[length - 6:length] == ".0.0.0":
                prefix_length = length - 6
            elif arg[length - 4:length] == ".0.0":
                prefix_length = length - 4
            elif arg[length - 2:length] == ".0":
                prefix_length = length - 2
            else:
                prefix_length = length

            for pkt in packets:
                if pkt[1][9][0:prefix_length] == arg[0:prefix_length] or pkt[1][10][0:prefix_length] == \
                        arg[0:prefix_length]:
                    matched_packets.append(pkt)

    elif arg == "not":
        if len(arguments) == 0:
            print("\"not\" cannot be the last argument.")
            sys.exit()
        else:
            arg = arguments.popleft()
            if arg == "host":
                if len(arguments) == 0:
                    print("A host IP address should be followed by the host command.")
                    sys.exit()
                else:
                    # ip address here
                    arg = arguments.popleft()
                    for pkt in packets:
                        dest_ip = pkt[1][10]
                        src_ip = pkt[1][9]
                        if arg != dest_ip and arg != src_ip:
                            matched_packets.append(pkt)
            elif arg == "ip":
                for pkt in packets:
                    if str(pkt[0][3]) != "0800":
                        matched_packets.append(pkt)
            elif arg == "port":
                if len(arguments) == 0:
                    print("\"port\" cannot be the last argument.")
                    sys.exit()
                else:
                    # port number
                    arg = arguments.popleft()
                    for pkt in packets:
                        if pkt[1][7] == 6 or pkt[1][7] == 17:
                            if str(pkt[2][0]) != arg and str(pkt[2][1]) != arg:
                                matched_packets.append(pkt)
            elif arg == "tcp":
                for pkt in packets:
                    if pkt[1][7] != 6:
                        matched_packets.append(pkt)
            elif arg == "udp":
                for pkt in packets:
                    if pkt[1][7] != 17:
                        matched_packets.append(pkt)
            elif arg == "icmp":
                for pkt in packets:
                    if pkt[1][7] != 1:
                        matched_packets.append(pkt)
            elif arg == "net":
                if len(arguments) == 0:
                    print("\"net net\" is required. ")
                    sys.exit()
                else:
                    # ip prefix
                    arg = arguments.popleft()
                    if len(arg.split(".")) != 4:
                        print("Please enter a valid ip address format. (x.x.x.x)")
                        sys.exit()
                    prefix_length = 0

                    length = len(arg)
                    if arg == "0.0.0.0":
                        prefix_length = 0

                    elif arg[length - 6:length] == ".0.0.0":

                        prefix_length = length - 6
                    elif arg[length - 4:length] == ".0.0":
                        prefix_length = length - 4
                    elif arg[length - 2:length] == ".0":
                        prefix_length = length - 2
                    else:
                        prefix_length = length
                    for pkt in packets:
                        if pkt[1][9][0:prefix_length] != arg[0:prefix_length] and pkt[1][10][0:prefix_length] != \
                                arg[0:prefix_length]:
                            matched_packets.append(pkt)

    return matched_packets, arg


def main():
    """
    Main function to set up everything and run the program.
    :return:
    """
    arguments = collections.deque(sys.argv)
    arguments.popleft()
    file_name = arguments.popleft()
    if len(arguments) == 0:
        print("Please enter filter commands to run the program. (host, port, ip, tcp, udp, icmp, net)")
        sys.exit()
    packets_info = read_and_store_pcap(file_name)
    handle_commands(packets_info, arguments)


if __name__ == "__main__":
    main()
