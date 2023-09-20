#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>


/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    unsigned short tcp_sport;               /* source port */
    unsigned short tcp_dport;               /* destination port */
    unsigned int   tcp_seq;                 /* sequence number */
    unsigned int   tcp_ack;                 /* acknowledgement number */
    unsigned char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)	(((th)->tcp_offx2 & 0xf0) >>4)
    unsigned char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    unsigned short tcp_win;                 /* window */
    unsigned short tcp_sum;                 /* checksum */
    unsigned short tcp_urp;                 /* urgent pointer */
    unsigned char tcp_payload[0];
#define TCP_PAYLOAD_MAXLEN 0x10
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  printf("       Src MAC: %02X-%02X-%02X-%02X-%02X-%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  printf("       Dst MAC: %02X-%02X-%02X-%02X-%02X-%02X\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader *ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("        Src IP: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("        Dst IP: %s\n", inet_ntoa(ip->iph_destip));    

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
	{
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + 4 * ip->iph_ihl);
	    printf("      Src Port: %d\n", ntohs(tcp->tcp_sport));
	    printf("      Dst Port: %d\n", ntohs(tcp->tcp_dport));	    
	    printf("      Message: ");
	    int i;
	    int messagelength = ntohs(ip->iph_len) - 4 * ip->iph_ihl - 4 * TH_OFF(tcp);
	    messagelength = messagelength < TCP_PAYLOAD_MAXLEN ? messagelength : TCP_PAYLOAD_MAXLEN;
	    for (i = 0; i < messagelength; i++){
		printf("%02X", tcp->tcp_payload[4 * TH_OFF(tcp) - 20 + i]);
		if(i % 2 == 1)
		    printf(" ");
	    }
	    printf("\n");
	    printf("Ascii Message: ");
	    for (i = 0; i < messagelength; i++){
		printf(" %c", tcp->tcp_payload[4 * TH_OFF(tcp) - 20 + i]);
		if(i % 2 == 1)
		    printf(" ");
	    }
	    printf("\n\n");
            return;
	}
        default:
            printf("   Protocol: others\n\n");
            return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


