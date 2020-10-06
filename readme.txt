CSCI351
Lyan Ye(yxy6465)

To run the program:
1. run it in Pycharm or other IDE with parameter (filename filter commands)
2. run it in terminal with by python pktsniffer.py project1.pcap filter commands

useful commands: host ip_address, ip, net ip_prefix(127.0.0.0 will be prefix of 127), 
		 tcp, udp, icmp, port, and ___, or ___, not ___

Notice:
1. since there are all ip packets, to display all the packets, simply do python pktsniffer.py project1.pcap ip
2. If there is only -c n flag in the arguments, I assume this flag is only for display n packets, 
	the program will display the first n packets. Otherwise, combined -c with other filters, it will
	display the first n filtered packets.