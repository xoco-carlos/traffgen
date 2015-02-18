/**
 * @file traffgen.c
 * @author Tovar Balderas Sergio Anduin 
 * @author Zamora Parra Xocoyotzin Carlos 
 * @date 17 Octubre 2014
 * @brief Network traffic generator for IPv4 & IPv6
 *
 * @see www.seguridad.unam.mx
 * @see tic.unam.mx
 * @see www.unam.mx
 */

#include <argp.h>
#include <argz.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#ifndef HI_PORT
#define HI_PORT 65535
#endif
#ifndef LO_PORT
#define LO_PORT 32768
#endif

unsigned short in_cksum(unsigned short *, int);

const char *argp_program_bug_address = "xzamora@seguridad.unam.mx and stovar@seguridad.unam.mx";
const char *argp_program_version = "version 1.0";

static char doc[]="Simple packet's crafter\vWith great power comes great responsability";
static char args_doc[]="IP_DST";
struct argp_option options[] ={
	{0,0,0,0, "IP Version:\n",1},
	{"ip4",'4',0,0,"IPv4 Packet"},
	{"ip6",'6',0,0,"IPv6 Packet"},
	
	{0,0,0,0, "Protocols:\n",2},
	{"icmp"	,1111,0,0,"ICMP Packet"},
	{"udp"	,2222,0,0,"UDP Packet"},
	{"tcp"	,3333,0,0,"TCP Packet"},

	{0,0,0,0, "ICMP Type and Code fields:\n",6},
	{"type"	,4444	,"NUM"	,0,"Type ICMP"},
	{"code"	,5555	,"NUM"	,0,"Code ICMP"},
	
	{0,0,0,0, "The following options could be grouped together after --tcp flag:\n",3},
	{0,'S',0,0,"Set SYNCHRONIZATION Flag"},
	{0,'A',0,0,"Set ACKNOWLEDGE Flag"},
	{0,'F',0,0,"Set FIN Flag"},
	{0,'P',0,0,"Set PUSH Flag"},
	{0,'R',0,0,"Set RESET Flag"},
	{0,'U',0,0,"Set URGENT Flag"},

	{0,0,0,0, "Number of packets:\n",5},
	{"fast"	,1000	,0	,0,"Send 100 packets per second"},
	{"flood",1001	,0	,0,"Send many packets as possible"},
	{"count",'c'	,"NUM"	,0,"Send NUM packets, one per second"},

	{0,0,0,0, "Customize your packets:\n",4},
	{"sport"	,'x',"NUM"	,0,"Source port"},
	{"dport"	,'y',"NUM"	,0,"Destination port"},
	{"saddr"	,'s',"IP"	,0,"Set a fake source IP address"},
	{"payload"	,'p',"STR"	,0,"Include a message in the payload"},
	
	{0,0,0,0, "Miscelaneous:\n",-1},
	{"verbose"	,'v',0,0,"Produce verbose output" },
	{0}
};
/**
 * @brief Struct for arguments on command line
 *
 * These arguments define the variables that you can use the program from the command line.
 */
struct arguments{
	char ip_ver;			/**< IP Version*/
	char protocol;			/**< Protocol to send*/
	char *argz;			/**< All arguments*/
	unsigned long daddr;		/**< Destination ip*/
	unsigned long saddr;		/**< Source ip*/
	char *payload;			/**< Payload packet*/
	size_t argz_len;		/**< # of args*/
	int syn,ack,fin,psh,rst,urg;	/**< TCP Flags*/
	int verbose,fast,flood;		/**< Boolean options*/
	unsigned int sport,dport;	/**< Port number*/
	unsigned int count;		/**< Number of packets to send*/
	int proto,port,tcpf;		/**< Control flags*/
	struct in6_addr saddr6;		/**< Struct for source inet address IPv6*/
	struct in6_addr daddr6;		/**< Struct for destination inet address IPv6*/
	char *sa,*da;				
	int delay;			/**< Delay */
	int typeicmp;			/**< Type ICMP*/
	int codeicmp;			/**< Code ICMP*/
};
/**
 * @brief Function to validate arguments
 *
 * The arguments are validated for each of the options on the command line.
 */
static int parse_opt (int key, char *arg, struct argp_state *state){
	struct arguments *a = state->input;
	switch (key){
		case 1111:		/**< ICMP Protocol*/
			a->protocol=IPPROTO_ICMP;
			a->proto++;
		break;
		case 2222:		/**< UDP Protocol*/
			a->protocol=IPPROTO_UDP;
			a->proto++;
		break;
		case 3333:		/**< TCP Protocol*/
			a->protocol=IPPROTO_TCP;
			a->proto++;
		break;
		case 4444:		/**< Type icmp*/
			a->typeicmp=(unsigned int)atoi(arg);
		break;
		case 5555:		/**< Code icmp*/
			a->codeicmp=(unsigned int)atoi(arg);
		break;
		case 1000:		/**< Send fast packets*/
			a->fast++;
		break;
		case 1001:		/**< Send flood*/
			a->flood++;
		break;
		case '4':		/**< IPv4*/
			a->ip_ver=4;
		break;
		case '6':		/**< IPv6*/
			a->ip_ver=6;
		break;
		case 'c':		/**< Count the packets*/
			a->count=(unsigned int)atoi(arg);
		break;
		case 'p':		/**< Payload*/
			a->payload=arg;
		break;
		case 's':		/**< Source IP*/
			a->sa=arg;
		break;
		case 'v':		/**< Verbose*/
			a->verbose=1;
		break;
		case 'x':		/**< Source Port*/
			a->sport=(unsigned int)atoi(arg);
			a->port++;
		break;
		case 'y':		/**< Destination Port*/
			a->dport=(unsigned int)atoi(arg);
			a->port++;
		break;
		case 'S':		/**< SYN Flag*/
			a->syn=1;
			a->tcpf++;
		break;
		case 'A':		/**< ACK Flag*/
			a->ack=1;
			a->tcpf++;
		break;
		case 'F':		/**< FIN Flag*/
			a->fin=1;
			a->tcpf++;
		break;
		case 'P':		/**< PSH Flag*/
			a->psh=1;
			a->tcpf++;
		break;
		case 'R':		/**< RST Flag*/
			a->rst=1;
			a->tcpf++;
		break;
		case 'U':		/**< URG Flag*/
			a->urg=1;
			a->tcpf++;
		break;
		case ARGP_KEY_ARG:
			argz_add (&a->argz, &a->argz_len, arg);
			a->da=arg;
		break;
		case ARGP_KEY_INIT:	/**< Initialize variables from the command line*/
			a->argz = 0;
			a->argz_len = 0;
			a->ip_ver=4;
			a->protocol=IPPROTO_ICMP;
			a->saddr=0;
			a->daddr=0;
			a->sa=NULL;
			a->da=NULL;
			a->payload="";
			a->count=-1;
			a->sport=-1;
			a->dport=-1;
			a->syn=0;
			a->ack=0;
			a->fin=0;
			a->psh=0;
			a->rst=0;
			a->urg=0;
			a->fast=1;
			a->flood=0;
			a->verbose=0;
			a->proto=0;
			a->port=0;
			a->tcpf=0;
			a->delay=1000000;
			a->typeicmp=8;
			a->codeicmp=0;
		break;
		case ARGP_KEY_END:{
			size_t count = argz_count (a->argz, a->argz_len);
			if (count > 1){				/**< Check only one argument*/
				argp_usage(state);
				argp_failure (state, 1, 0, "too many arguments");
			}
			else if (count < 1){
				argp_usage(state);
				argp_failure (state, 1, 0, "too few arguments");
			}
			if(a->ip_ver == IPPROTO_IPIP){	/**< Check IPv4 address(es)*/
				if(a->sa != NULL)
					if (inet_pton(AF_INET, a->sa, &(a->saddr)) != 1)
						argp_failure (state, 1, 0, "Bad source IP address, try again");
				if (inet_pton(AF_INET, a->da, &(a->daddr)) != 1)
					argp_failure (state, 1, 0, "Bad destination IP address, try again");
			}
			if(a->ip_ver == IPPROTO_TCP){	/**< Check IPv6 address(es)*/
				if(a->protocol==IPPROTO_ICMP)
					a->protocol=IPPROTO_ICMPV6;
				if(a->typeicmp == 8)
					a->typeicmp=128;
				if(a->sa != NULL)
					if (inet_pton(AF_INET6, a->sa, &(a->saddr6)) != 1)
						argp_failure (state, 1, 0, "Bad source IP address, try again");
				if (inet_pton(AF_INET6, a->da, &(a->daddr6)) != 1)
					argp_failure (state, 1, 0, "Bad destination IP address, try again");
			}
			if(a->proto>1)	/**< More than one protocol specified*/
				argp_failure (state, 1, 0, "You must specify only one protocol");
			if((a->protocol==IPPROTO_ICMP || a->protocol==IPPROTO_ICMPV6) && (a->port)>0) /**< IPPROTO_ICMP with port*/
				argp_failure (state, 1, 0, "You can not specify a port for IPPROTO_ICMP");
			if(a->protocol==IPPROTO_ICMP && (a->tcpf)>0)	/**< IPPROTO_ICMP with tcp flags*/
				argp_failure (state, 1, 0, "You can not specify a tcp flags for IPPROTO_ICMP");
			if(a->protocol==IPPROTO_ICMP && (a->typeicmp)<0)	/**< IPPROTO_ICMP with negative type*/
				argp_failure (state, 1, 0, "You can not specify a negative type for IPPROTO_ICMP");
			if(a->protocol==IPPROTO_ICMP && (a->codeicmp)<0)	/**< IPPROTO_ICMP with negative code*/
				argp_failure (state, 1, 0, "You can not specify a negative code for IPPROTO_ICMP");
			if(a->protocol==IPPROTO_UDP && (a->tcpf)>0)	/**< IPPROTO_UDP with tcp flags*/
				argp_failure (state, 1, 0, "You can not specify a tcp flags for IPPROTO_UDP");
			if(a->dport==-1 && (a->protocol==IPPROTO_UDP || a->protocol==IPPROTO_TCP))	/**< IPPROTO_UDP or IPPROTO_TCP without destination port*/
				argp_failure (state, 1, 0, "You must specify a destination port");
			if((a->protocol==IPPROTO_UDP || a->protocol==IPPROTO_TCP) && (a->dport < 1 || a->dport > HI_PORT) )	/**< Destination port number out of range*/
				argp_failure (state, 1, 0, "Port number out of range. It must be between 1 and 65535");
			if((a->protocol==IPPROTO_UDP || a->protocol==IPPROTO_TCP) && (a->sport < 1 || a->sport > HI_PORT) ){	/**< Source port number out of range, set random*/
				srand(time(NULL));
				a->sport=(rand()%(HI_PORT-LO_PORT))+LO_PORT;
			}
			if(a->flood > 0) /**< Flood*/
				a->delay=0;
			else 
				if(a->fast > 0) /**< One or more parameters fast*/
					a->delay=a->delay-(a->fast*100000);
		}
		break;
	}
	return 0;
}

/**
 * @brief Struct for arguments.
 *
 * Defines the structure for arguments.
 */
struct argp argp = { options, parse_opt, args_doc, doc};

/**
 * @brief Main function of traffgen
 *
 * The main function of traffgen makes creating and sending packets.
 */
int main(int argc, char **argv){
	
	struct arguments a;
	int packet_size;
	int payload_size;
	int sent=0;
	int sent_size;
	int on;
	int sockfd;
	int header_length;
	char *data; 
	char *packet;
	struct iphdr *ip;
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct ip6_hdr *ip6;
	struct icmphdr *icmp;
	struct icmp6_hdr *icmp6;
	struct sockaddr_in servaddr;
	struct sockaddr_in6 servaddr6;
	
	if (argp_parse (&argp, argc, argv, 0, 0, &a) == 0){
		if(a.verbose)
			printf("IP version:\t%i\nProtocol:\t%i\nDestination IP:\t%s\nSource IP:\t%s\nPayload:\t%s\nSYN:\t%i\nACK:\t%i\nFIN:\t%i\nPSH:\t%i\nRST:\t%i\nURG:\t%i\nVerbose:\t%i\nFast:\t%i\nFlood:\t%i\nSport:\t%i\nDport:\t%i\nCount:%i\n",
			a.ip_ver,
			a.protocol,
			a.da,
			a.sa,
			a.payload,
			a.syn,
			a.ack,
			a.fin,
			a.psh,
			a.rst,
			a.urg,
			a.verbose,
			a.fast,
			a.flood,
			a.sport,
			a.dport,
			a.typeicmp,
			a.codeicmp,
			a.count
		);
	}

	payload_size = strlen(a.payload);
	on=1;
	/*Creating RAW Socket*/
	if(a.ip_ver==IPPROTO_IPIP){
		servaddr.sin_family		= AF_INET;
		servaddr.sin_addr.s_addr= a.daddr;
		header_length			= sizeof (struct iphdr);
		sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	}
	else{
		servaddr6.sin6_family	= AF_INET6;
		servaddr6.sin6_addr		= a.daddr6;
		servaddr6.sin6_port		= 0;
		servaddr6.sin6_flowinfo	= 0;
		servaddr6.sin6_scope_id	= 0;
		header_length			= sizeof(struct ip6_hdr);
		sockfd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
	}
	/*Socket error*/
	if (sockfd < 0){ perror("Could not create socket");return (0);}
	/*We shall provide IP headers*/
	if(a.ip_ver==IPPROTO_IPIP){
		if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) {
			perror("setsockopt"); return (0);
		}
		//allow socket to send datagrams to broadcast addresses
		if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) {
			perror("setsockopt"); return (0);
		}	   
	}
	if (!packet){perror("out of memory"); close(sockfd); return (0);}
	/*Check protocol*/
	if(a.protocol == IPPROTO_UDP)
		packet_size = header_length + sizeof (struct udphdr) + payload_size;
	else if(a.protocol == IPPROTO_TCP)
		packet_size = header_length + sizeof (struct tcphdr) + payload_size;
	else if(a.protocol == IPPROTO_ICMPV6)
		packet_size = header_length + sizeof (struct icmp6_hdr) + payload_size;
	else
		packet_size = header_length + sizeof (struct icmphdr) + payload_size;
	
	/*Allocating memory*/
	packet = malloc (packet_size);
	if(a.ip_ver==IPPROTO_IPIP)
		ip = (struct iphdr *) packet;
	else
		ip6 = (struct ip6_hdr *) packet;
	
	if(a.protocol == IPPROTO_UDP)
		udp = (struct udphdr *) (packet + header_length);
	else if(a.protocol == IPPROTO_TCP)
		tcp = (struct tcphdr *) (packet + header_length);
	else if(a.protocol == IPPROTO_ICMPV6)
		icmp6 = (struct icmp6_hdr *) (packet + header_length);
	else
		icmp = (struct icmphdr *) (packet + header_length);
	
	memset (packet, 0, packet_size);

	if(a.ip_ver==IPPROTO_IPIP){
		ip->version	= a.ip_ver;
		ip->saddr	= a.saddr;
		ip->daddr	= a.daddr;
		ip->ihl		= 5;
		ip->tos		= 0;
		ip->frag_off= 0;
		ip->ttl		= 255;
		ip->id		= rand ();
		ip->protocol= a.protocol;
		ip->tot_len	= htons (packet_size);
	}
	else{
		ip6->ip6_flow	= 0;
		ip6->ip6_vfc	= 0x60;
		ip6->ip6_hlim	= 0xff;
		ip6->ip6_plen	= htons(packet_size-40);
		ip6->ip6_nxt	= a.protocol;
		ip6->ip6_src	= a.saddr6;
		ip6->ip6_dst	= a.daddr6;
	}
	
	if(a.protocol == IPPROTO_UDP){
		udp->source	= htons(a.sport);
		udp->dest	= htons(a.dport);
		udp->len	= htons(8 + payload_size);
		udp->check	= 0;
		udp->check	= in_cksum((unsigned short *)udp, sizeof(struct udphdr) + payload_size);
		data			= (packet + header_length + sizeof(struct udphdr));
	}
	else if(a.protocol == IPPROTO_TCP){
		tcp->source	= htons(a.sport);
		tcp->dest	= htons(a.dport);
		tcp->fin	= a.fin;
		tcp->syn	= a.syn;
		tcp->rst	= a.rst;
		tcp->psh	= a.psh;
		tcp->ack	= a.ack;
		tcp->urg	= a.urg;
		tcp->seq 	= rand();
		tcp->doff 	= 5;	
		tcp->check	= 0;
		tcp->window	= htons (5840);
		tcp->urg_ptr= 0;
		tcp->ack_seq= rand();
		tcp->check	= in_cksum((unsigned short *)tcp, sizeof(struct tcphdr) + payload_size);
		data		= (packet + header_length + sizeof(struct tcphdr));
	}
	else if(a.protocol == IPPROTO_ICMPV6){
		icmp6->icmp6_type	= a.typeicmp;
		icmp6->icmp6_code	= a.codeicmp;
		icmp6->icmp6_cksum	= in_cksum((unsigned short *)icmp6, sizeof(struct icmp6_hdr) + payload_size);
		data			= (packet + header_length + sizeof(struct icmp6_hdr));
	}
	else{
		icmp->type	= a.typeicmp;
		icmp->code	= a.codeicmp;
		icmp->checksum	= 0;
		icmp->checksum	= in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + payload_size);
		icmp->un.echo.id= rand();
		icmp->un.echo.sequence = rand();
		data		= (packet + header_length + sizeof(struct icmphdr));
	}
	strcpy(data,a.payload);
	while (a.count > 0 || a.count == -1){
		if(a.ip_ver==IPPROTO_IPIP){
			if ((sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1){
				perror("send failed\n");
				break;
			}
		}
		else{
			if ((sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr6, sizeof (servaddr6))) < 1){
				perror("send failed\n");
				break;
			}
		}
		++sent;
		a.count--;
		printf("%d packets sent\r", sent);
		fflush(stdout);
		usleep(a.delay);	//microseconds
	}
	free(packet);
	close(sockfd);
	return (0);
}

/*
	Function calculate checksum
*/
/**
 * @brief Function calculate checksum.
 *
 * In this function calculate checksum.
 * @param *ptr 		Pointer to calculate the checksum.
 * @param nbytes 	Number of bytes of the packet.
 * @return Returns the checksum of packet.
 */
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long sum;
	u_short oddbyte;
	register u_short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *) & oddbyte) = *(u_char *) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}
