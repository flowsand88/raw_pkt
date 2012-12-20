/**
 *	@file: raw_pkt.c
 *
 *	gcc -o raw_pkt raw_pkt.c
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <linux/ip.h>
//#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <sys/select.h>
/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/ioctl.h>
#include <net/if.h>

typedef unsigned int       u32;
typedef signed int         s32;
typedef unsigned short     u16;
typedef signed short       s16;
typedef unsigned char      u8;
typedef signed char        s8;

#define BUILD_SEND_PACKET_JUST_ONCE

enum {
	RAW_SEND_MODE,
	RAW_RECV_MODE,
	RAW_INVALID_MODE,
};

struct _raw_option{
	int mode;
	int us;
	int count;
	int verbose;
	struct sockaddr_ll addr;
	char name[IFNAMSIZ];
}raw_options;

struct pkt_stat {
	unsigned long pkts;
	unsigned long bytes;
}cs, os;

const char dest_mac_addr[6] = {0x00, 0x90, 0x0b, 0x13, 0xb8, 0x36};
static volatile int running = 0;

u16 checksum(char *buf, int len)
{
    u32 csum = 0;
    u16 *word = (u16 *)buf;
    while (len > 1) {
        csum += *word++;
        len -= 2;
    }
    
    if (len)
        csum += *(u8 *)word;

    csum = (csum >> 16) + (csum & 0XFFFF);
    csum += (csum >> 16); 
    return (u16)~csum;
}


static int build_mac_hdr(struct ethhdr *eh, u16 protocol) {
	char source[6] = {0x00, 0x90, 0x0b, 0x1e, 0xe1, 0xa6};

	memcpy(eh->h_dest, dest_mac_addr, 6);
	memcpy(eh->h_source, source, 6);
	eh->h_proto = htons(protocol);

	return 0;
}

static int build_ipv4_hdr(struct iphdr *ih, u8 protocol, u32 saddr, u32 daddr, u8 *content, int length) {
	ih->ihl = 5;
	ih->version = 4;
	ih->tos = 0;
	ih->tot_len = htons(length + 20);
	ih->id = 0;
	ih->frag_off = 0;
	ih->ttl = 64;
	ih->protocol = protocol;
	ih->saddr = saddr;
	ih->daddr = daddr;
	ih->check = checksum((char *)ih, 20);

	return length + 20;
}

static int build_ipv6_hdr(struct ip6_hdr *ih, u8 protocol, u32 *saddr, u32 *daddr, u8 *content, int length) {
	ih->ip6_vfc = 0x60;
	ih->ip6_plen = htons(length);
	ih->ip6_nxt = protocol;
	ih->ip6_hops = 1;

	memcpy(&ih->ip6_src, saddr, 16);
	memcpy(&ih->ip6_dst, daddr, 16);

	return length + 40;
}

static int build_udp_hdr(struct udphdr *uh, u16 sport, u16 dport, u8 *content, u32 length) {
	uh->source = htons(sport);
	uh->dest = htons(dport);
	uh->len = htons(length);
	uh->check = checksum((char*)content, length);

	return length + 8;
}

static void help() {
	printf("Usage: raw [--send  [-c count] [-s speed | -t interval] | --recv [-v]] -i device\n"
			"   send mode:\n"
			"         -c count: how many packets should be send, default is 1000, 0 forever;\n"
			"         -s speed: how fast should packets be send, default is 10000/s;\n"
			"         -i interval: interval between packet send time, default is 100 micorsecond\n"
			"   recv mode:\n"
			"         -i ethname: netdevice name, ex eth0, eth1, etc.\n"
			"         -v: print sequence of every packet\n\n"
			);
}

int build_ipv4_pkt(char *buffer, u32 len, char *data, u32 dlen) {
	char *content;
	struct ethhdr *eh;
	struct iphdr *ih;
	struct udphdr *uh;
	int length;

	memset(buffer, 0, len);
	eh = (struct ethhdr *)buffer;
	ih = (struct iphdr *)(buffer + 14);
	uh = (struct udphdr *)(buffer + 14 + 20);
	content = (char *)uh + 8;

	memcpy(content, data, dlen);
	if(dlen < 18)
		dlen = 18;
	length = build_udp_hdr(uh, 26000, 62000, data, dlen);
	length = build_ipv4_hdr(ih, 17, 0x10102030, 0x10104030, (char *)uh, length);
	build_mac_hdr(eh, 0x0806);
	length += 14;

	return length;
}

int build_ipv6_pkt(char *buffer, u32 len, char *data, u32 dlen) {
	char *content;
	struct ethhdr *eh;
	struct ip6_hdr *ih;
	struct udphdr *uh;
	int length;
	u32 src[4] = {0x40000001, 0x45000005, 0x50000009};
	u32 dst[4] = {0x60000001, 0x65000002, 0x70000003};

	memset(buffer, 0, len);
	eh = (struct ethhdr *)buffer;
	ih = (struct ip6_hdr *)(buffer + 14);
	uh = (struct udphdr *)(buffer + 14 + 40);
	content = (char *)uh + 8;

	memcpy(content, data, dlen);

	length = build_udp_hdr(uh, 26000, 62000, data, dlen);
	length = build_ipv6_hdr(ih, 17, src, dst, (char *)uh, length);
	build_mac_hdr(eh, 0x0800);
	length += 14;

	return length;
}

inline void sleep_us(int us) {
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = us;

	select(0, NULL, NULL, NULL, &tv);
}

void timer_print(int sig) {
	unsigned long pkts = 0;
	unsigned long bytes = 0;

	char buf[64] = "";
    time_t tm = time(NULL);
#define CTIME_LEGTH 25

	ctime_r(&tm, buf);
	buf[CTIME_LEGTH -1] = 0;
	if(raw_options.mode == RAW_SEND_MODE) {
		pkts = cs.pkts - os.pkts;
		bytes = cs.bytes - os.bytes;
		os.pkts = cs.pkts;
		os.bytes = cs.bytes;

		if (pkts)
			printf("%s: send %lu packets, %lu bytes, packet avg_len %u.\n", buf, pkts, bytes, (u32)(bytes/pkts));
		else
			printf("%s: send %lu packets, %lu bytes.\n", buf, pkts, bytes);
	}
	else {
		pkts = cs.pkts - os.pkts;
		bytes = cs.bytes - os.bytes;
		os.pkts = cs.pkts;
		os.bytes = cs.bytes;
		if(pkts)
			printf("%s: recv %lu packets, %lu bytes, packet avg_len %lu\n", buf, pkts, bytes, (bytes/pkts));
		else
			printf("%s: recv %lu packets, %lu bytes\n", buf, pkts, bytes);
	}

	alarm(1);
}

void sig_int_hdl(int sig) {
	running = 0;
}

void start_send(struct _raw_option *op, int sock) {
	int forever = 0;
	unsigned long i = 0;
	int len = 0;
	int ret = 0;
	char buffer[1024];
	char seq[256] = "";
	//struct sockaddr_ll addr;

	//memcpy(&addr, &op->addr, sizeof(addr));

	if (op->count == 0)
		forever = 1;

	cs.pkts = 0;
	cs.bytes = 0;
	os.bytes = 0;
	os.pkts = 0;
	signal(SIGALRM, timer_print);
	alarm(1);

	running = 1;

#ifdef BUILD_SEND_PACKET_JUST_ONCE
	memset(seq, 0, sizeof(seq));
	snprintf(seq, sizeof(seq) - 1, "sequence = %lu", i);
	//printf("seq: %s len: %d\n", seq, strlen(seq));
	//ultoa(i, seq, 10);
	len = build_ipv4_pkt(buffer, sizeof(buffer), seq, strlen(seq));
#endif

	while(running && (forever || op->count > 0)) {
#ifndef BUILD_SEND_PACKET_JUST_ONCE
		memset(seq, 0, sizeof(seq));
		snprintf(seq, sizeof(seq) - 1, "sequence no %09lu", i);
		//printf("seq: %s len: %d\n", seq, strlen(seq));
		//ultoa(i, seq, 10);
		len = build_ipv4_pkt(buffer, sizeof(buffer), seq, strlen(seq));
#endif

		ret = sendto(sock, buffer, len, 0, (const struct sockaddr *)&(op->addr), sizeof(op->addr));
		if(ret < 0) {
			perror("sendto");
			printf("sll_family= %hu sll_protocol= %hu sll_ifindex= %d sll_hatype=%hu sll_pkttype=%u sll_halen=%u sll_addr: %x:%x:%x:%x:%x:%x\n", 
				op->addr.sll_family, op->addr.sll_protocol, op->addr.sll_ifindex, op->addr.sll_hatype, (u32)op->addr.sll_pkttype, (u32)op->addr.sll_halen,
				op->addr.sll_addr[0], op->addr.sll_addr[1],op->addr.sll_addr[2],op->addr.sll_addr[3],op->addr.sll_addr[4],op->addr.sll_addr[5]);
			break;
		}

		i ++;
		op->count --;

		cs.pkts ++;
		cs.bytes += ret;

		if(op->us)
			sleep_us(op->us);
	}

	alarm(0);

	printf("\nTotally send %d packets, %lu bytes, avg_len %u byte, result: %s.\n", i, cs.bytes, (u32)(cs.bytes/cs.pkts), ret < 0 ? "failed" : "success");
}

void start_recv(struct _raw_option *op, int sock) {
	int ret = 0;
	char buffer[1600] = "";

	cs.pkts = 0;
	cs.bytes = 0;
	os.pkts = 0;
	os.bytes = 0;
	signal(SIGALRM, timer_print);
	alarm(1);

	running = 1;

	while(running) {
		ret = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
		if(ret < 0) {
			perror("recv");
			break;
		}
		
		cs.pkts ++;
		cs.bytes += ret;
	}

	alarm(0);

	printf("\nTotally recv %lu packets, %lu bytes, avg_len %u bytes.\n", cs.pkts, cs.bytes, (u32)(cs.bytes/cs.pkts));
}

int create_socket() {
	int sock = 0;
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock < 0) {
		perror("create raw socket failed!");
		return -1;
	}

	return sock;
}

int parse_options(int argc, char *argv[], struct _raw_option *op) {
	int c;
	int option_index = 0;
	static struct option long_options[] = {
		{"send", 0, 0, 0},
		{"recv", 0, 0, 0},
		{0, 0, 0, 0}
	};

	memset(op, 0, sizeof(*op));
	op->mode = RAW_INVALID_MODE;
	op->us = 500;
	op->count = 1000;
	op->verbose = 0;

	while(-1 != (c = getopt_long(argc, argv, "c:s:i:t:vh",
                        long_options, &option_index)))
	{
		int speed = 0;
		switch(c) {
			case 0:
				if(strcmp(long_options[option_index].name, "send") == 0)
					op->mode = RAW_SEND_MODE;
				else if(strcmp(long_options[option_index].name, "recv") == 0)
					op->mode = RAW_RECV_MODE;
				else {
					printf("unsupport mode, must be send or recv\n");
					return -1;
				}
				break;
			case 'c':
				if(op->mode == RAW_SEND_MODE)
					op->count = atoi(optarg);
				else
					printf("The option -c only support at RAW_SEND_MODE.\n");
				break;
			case 's':
				if(op->mode == RAW_SEND_MODE)
					speed = atoi(optarg);
				else
					printf("The option -s only support at RAW_SEND_MODE.\n");

				op->us = 1000000/speed;
				break;
			case 'i':
				strncpy(op->name, optarg, IFNAMSIZ - 1);
				break;
			case 't':
				if(op->mode == RAW_SEND_MODE)
					op->us = atoi(optarg);
				else
					printf("The option -t only support ar RAW_SEND_MODE.\n");
				break;
			case 'v':
				if(op->mode == RAW_RECV_MODE)
					op->verbose = atoi(optarg);
				else
					printf("The option -v only support at RAW_RECV_MODE.\n");
				break;
			case 'h':
				help();
				exit(0);
			default:
				printf("got unexpect option: %c.\n", (char)c);
				break;
		}
	}

	if(op->mode == RAW_INVALID_MODE) {
		printf("mode must be send or recv!\n");
		return -1;
	}
	
	printf("mode: %s count: %d interval: %dus verbos: %s ifname: %s\n", op->mode == RAW_SEND_MODE ? "send" : "recv", op->count, op->us, op->verbose ? "True" : "False", op->name);

	return 0;
}

static int set_promisc(int sock, char * ifname) {
	int ret;
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if(ret < 0) {
		printf("get socket %d FLAG failed!\n", sock);
		return -1;
	}

	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl (sock, SIOCSIFFLAGS, &ifr) == -1) {
		perror("Error: Could not set flag IFF_PROMISC");
		return -1;
	}

	return ret;
}

static int clear_promisc(int sock, char * ifname) {
	int ret;
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if(ret < 0) {
		printf("get socket %d FLAG failed!\n", sock);
		return -1;
	}

	ifr.ifr_flags &= ~IFF_PROMISC;
	if (ioctl (sock, SIOCSIFFLAGS, &ifr) == -1) {
		perror("Error: Could not clear flag IFF_PROMISC");
		return -1;
	}

	return ret;
}

int main(int argc, char *argv[]) {
	int sock = 0;
	int ret = 0;
	int ifindex = 0;
	struct ifreq req;
	struct sockaddr_ll addr;

	ret = parse_options(argc, argv, &raw_options);
	if(ret < 0)
		exit(-1);

	sock =  create_socket();
	if(sock < 0)
		exit(-1);

	strncpy(req.ifr_name, raw_options.name, IFNAMSIZ);
	ret = ioctl(sock, SIOCGIFINDEX, &req);
	if(ret < 0) {
		perror("ioctl:");
		exit(-1);
	}

	ifindex = req.ifr_ifindex;
	printf("device %s ifindex: %d\n", raw_options.name, ifindex);

	memset(&addr, 0, sizeof(addr));
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = ifindex;
	addr.sll_family = AF_PACKET;


	signal(SIGINT, sig_int_hdl);
	if(raw_options.mode == RAW_RECV_MODE) {
		ret = bind(sock, (const struct sockaddr *)&addr, sizeof(addr));
		if(ret < 0) {
			perror("bind");
			exit(-1);
		}
		raw_options.addr.sll_family = AF_PACKET;
		raw_options.addr.sll_hatype = 1;
		raw_options.addr.sll_pkttype = PACKET_OTHERHOST;

		set_promisc(sock, raw_options.name);
		start_recv(&raw_options, sock);
		clear_promisc(sock, raw_options.name);
	}
	else {
		raw_options.addr.sll_family = AF_PACKET;
		memcpy(raw_options.addr.sll_addr, dest_mac_addr, 6);
		raw_options.addr.sll_halen = 6;
		raw_options.addr.sll_ifindex = ifindex;

		start_send(&raw_options, sock);
	}

	return 0;
}

