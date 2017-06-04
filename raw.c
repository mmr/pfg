#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define SRC_ADDR "127.0.0.1"
#define DST_ADDR "127.0.0.1"
#define SRC_PORT 6666
#define DST_PORT 80

unsigned short in_cksum(unsigned short *, int);

int
main(int argc, char **argv) {
    // pacote
    unsigned char packet[sizeof(struct ip) + sizeof(struct tcphdr)];

    // cabecalho ip
    struct ip *iphdr = (struct ip*) packet;
    memset(iphdr, 0, sizeof(struct ip));
    iphdr->ip_src.s_addr = inet_addr(SRC_ADDR);
    iphdr->ip_dst.s_addr = inet_addr(DST_ADDR);
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_len = htons((sizeof(struct ip) + sizeof(struct tcphdr)));
    iphdr->ip_id = htons(getpid());
    iphdr->ip_ttl = 60;
    iphdr->ip_p   = IPPROTO_TCP;
    iphdr->ip_sum = (u_short) in_cksum((unsigned short *) iphdr,
        sizeof(struct ip));

    // cabecalho tcp
    struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct ip));
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->source = htons(SRC_PORT);
    tcp->dest = htons(DST_PORT);
    tcp->seq = htonl(random()%time(NULL));
    tcp->ack = htonl(random()%time(NULL));
    tcp->syn = 1;
    tcp->window = htons(TCP_MAXWIN);
    tcp->check = in_cksum((unsigned short*) tcp, sizeof(struct tcphdr));

    // sock
    struct sockaddr_in mysock;
    memset(&mysock, 0, sizeof(mysock));
    mysock.sin_family = AF_INET;
    mysock.sin_addr.s_addr = iphdr->ip_src.s_addr;

    int p_len = sizeof(packet);
    socklen_t s_len = (socklen_t) sizeof(struct sockaddr_in);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    sendto(sock, &packet, p_len, 0, (struct sockaddr *) &mysock, s_len);
    return 0;
}

/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
unsigned short
in_cksum(unsigned short *addr, int len) {
    register int sum = 0;
    register u_short *w = addr;
    register int nleft = len;
    u_short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum) , we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w ;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    return(answer);
}
