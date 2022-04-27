#include <pcap.h>
#include <stdio.h>

// Code provided by tcpdump.org
#include "sniffex.c"

// /* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

int packetNum = 0;

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
   printf("Got a packet %d\n", packetNum++);

   ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
   size_ip = IP_HL(ip)*4;

   printf("\tSource: %s\n", inet_ntoa(ip->ip_src));
   printf("\tDestination: %s\n", inet_ntoa(ip->ip_dst));

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    printf("\tSource port TCP: %d\n", ntohs(tcp->th_sport));
    printf("\tDestination port TCP: %d\n", ntohs(tcp->th_dport));

    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0) {
		printf("----Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
        printf("\n");
	}
}

int main(int argc, char *argv[]){
   pcap_t *handle;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct bpf_program fp;
   //char filter_exp[500];
   char filter_exp[500];
   if (argc == 1) {
       strcpy(filter_exp, "icmp and dst host 10.0.2.15 and src host 142.250.68.174");
   } else if (argc == 3) {
       strcpy(filter_exp, "src portrange ");
       strcat(filter_exp, argv[1]);
       strcat(filter_exp, "-");
       strcat(filter_exp, argv[2]);
   } else {
       printf("Expected 0 or 2 arguments.");
       exit(0);
   }
   printf("FILTER %s\n",filter_exp);
   bpf_u_int32 net;
   // Step 1: Open live pcap session on NIC with name ethx
   // you need to change "eth3" to the name
   // found on their own machines (using ifconfig).
   handle = pcap_open_live(/*"ethx"*/"enp0s3", BUFSIZ, 1, 1000, errbuf);
   // Step 2: Compile filter_exp into BPF psuedo-code
   pcap_compile(handle, &fp, filter_exp, 0, net);
   pcap_setfilter(handle, &fp);
   // Step 3: Capture packets
   pcap_loop(handle, -1, got_packet, NULL);
   pcap_close(handle); //Close the handle
   return 0;
}
// Note: donâ€™t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap