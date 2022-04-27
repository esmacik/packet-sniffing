Erik Macik
Assignment 3

Running scapy_sniff.py
- This code is just link the code provided in the Assignment 3 description.
- There are 2 lines of edited code, and if you'd like to run it please comment out one of them (line 6 or 7).
- Line 6 and 7 each have one of the Scapy filters applied to it per the assignment description

Running mySniffer.c
- This code is just line the starter code provided by Dr. Tosh.
- To run, please do the following on a virtual machine.
    - Compile the program with the command "gcc mySniffer.c -o mySniffer.o -lpcap"
    - Run the program with root privilages as "sudo ./mySniffer.o"
    - If no command line arguments are given, ICMP packets from a predetermined source and destination will be captured.
    - You can also run with 2 number command line arguments as port ranges to receive tcp packets from that port ranges
        - Ex: To receive TCP packets in the port range 0-9999: "sudo ./mySniffer.o 0 9999"