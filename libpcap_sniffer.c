#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ether_header *ep;
    struct ip *iph;
    unsigned short ether_type;
    int chcnt = 0;
    int len = pkthdr->len;
    int i;

	for(i=0;i<pkthdr->len;i++) 
	{ 
         printf("%02x ", packet[i]);
             
    }
	 printf("\n");
	 
	 printf("dest mac: %02x %02x %02x %02x %02x %02x \n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
	 printf("src mac: %02x %02x %02x %02x %02x %02x \n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
	 printf("type: %02x %02x \n", packet[12], packet[13]);
	 
	 printf("src ip: %d.%d.%d.%d \n", packet[26], packet[27], packet[28], packet[29]);
	 printf("dst ip: %d.%d.%d.%d \n", packet[30], packet[31], packet[32], packet[33]);
	 printf("protocol: %d \n", packet[23]);
	 
    // Get Ethernet header.
    ep = (struct ether_header *)packet;
    // Get upper protocol type.
    ether_type = ntohs(ep->ether_type);
    
    

    if (ether_type == ETHERTYPE_IP) {
        printf("ETHER Source Address = ");
        for (i=0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_shost[i]);
        printf("\n");
        printf("ETHER Dest Address = ");
        for (i=0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_dhost[i]);
        printf("\n");

        // Move packet pointer for upper protocol header.
        //packet += sizeof(struct ether_header);
        iph = (struct ip *)(packet+sizeof(struct ether_header));
        printf("IP Ver = %d\n", iph->ip_v);
        printf("IP Header len = %d\n", iph->ip_hl<<2);
        printf("IP Source Address = %s\n", inet_ntoa(iph->ip_src));
        printf("IP Dest Address = %s\n", inet_ntoa(iph->ip_dst));
        printf("IP Packet size = %d\n", len-16);
    }
}

int main(int argc, char **argv)
{
  char *dev;
  char *net;
  char *mask;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  pcap_t *pcd; // packet caputre descriptor.
  bpf_u_int32 netp;
  bpf_u_int32 maskp;
  struct in_addr net_addr, mask_addr;

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL)
  {
      printf("%s\n", errbuf);
      exit(1);
  }
  printf("DEV : %s\n", dev);

  // Get netmask
  if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
    fprintf(stderr, "%s\n", errbuf);
    return 1;
  }
  net_addr.s_addr = netp;
  net = inet_ntoa(net_addr);
  printf("NET : %s\n", net);
  mask_addr.s_addr = maskp;
  mask = inet_ntoa(mask_addr);
  printf("MASK : %s\n", mask);

  // Get packet capture descriptor.
  pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
  if (pcd == NULL) {
    fprintf(stderr, "%s\n", errbuf);
    return 1;
  }

  // Set compile option.
  if (pcap_compile(pcd, &fp, "tcp", 0, netp) == -1) {
    fprintf(stderr, "compile error\n");
    return 1; }

  // Set packet filter role by compile option.
  if (pcap_setfilter(pcd, &fp) == -1) {
    fprintf(stderr, "set filter error\n");
    return 1;
  }

  // Capture packet. When packet captured, call callback function.
  pcap_loop(pcd, 0, callback, NULL);
  return 0;
} 