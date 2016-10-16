#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <string.h>

/* just print a count every time we have a packet...                        */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
		packet)
{
	unsigned short ethertype;
	memcpy(&ethertype, packet + 12, sizeof(ethertype));
	if (ntohs(ethertype) != 0x0800)
	{
		printf("invalid ethertype (%hx)\n", ethertype);
		return;
	}
	struct iphdr iphdr;
	memcpy(&iphdr, packet + 14, sizeof(iphdr));
	if (iphdr.protocol == IPPROTO_TCP)
	{
		printf("TCP\n");
	}
	else if (iphdr.protocol == IPPROTO_ICMP)
	{
		printf("ICMP\n");
	}
	else
		printf("unknown protocol\n");
}

int main(int argc,char **argv)
{ 
	int i;
	char *dev; 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;     /* pcap.h                    */
	struct ether_header *eptr;  /* net/ethernet.h            */
	struct bpf_program fp;      /* hold compiled program     */
	bpf_u_int32 maskp;          /* subnet mask               */
	bpf_u_int32 netp;           /* ip                        */


	if(argc != 2){ fprintf(stdout,"Usage: %s \"filter program\"\n"
	        ,argv[0]);return 0;}

	/* grab a device to peak into... */
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{ fprintf(stderr,"%s\n",errbuf); exit(1); }

	/* ask pcap for the network address and mask of the device */
	pcap_lookupnet(dev,&netp,&maskp,errbuf);

	/* open device for reading this time lets set it in promiscuous
	 * mode so we can monitor traffic to another machine             */
	descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
	if(descr == NULL)
	{ printf("pcap_open_live(): %s\n",errbuf); exit(1); }

	/* Lets try and compile the program.. non-optimized */
	if(pcap_compile(descr,&fp,argv[1],0,netp) == -1)
	{ fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

	/* set the compiled program as the filter */
	if(pcap_setfilter(descr,&fp) == -1)
	{ fprintf(stderr,"Error setting filter\n"); exit(1); }

	/* ... and loop */ 
	pcap_loop(descr,-1,my_callback,NULL);

	return 0;
}

