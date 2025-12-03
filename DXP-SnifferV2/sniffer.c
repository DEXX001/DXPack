#include <sys/socket.h>    // Pour socket()
#include <arpa/inet.h>     // Pour inet_addr() (convertir IP texte en binaire)
#include <net/ethernet.h>  // Pour struct ether_header
#include <netinet/if_ether.h> // Pour struct ether_arp
#include <net/if.h>        // Pour obtenir l'index de l'interface (nécessaire pour envoyer)
#include <sys/ioctl.h>     // Pour communiquer avec le pilote réseau
#include <linux/if_packet.h> // Pour struct sockaddr_ll (l'adresse de destination bas niveau)
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define GREEN "\033[32m"
#define RESET "\033[0m"


int main(int ac, char **av)
{
    if (ac != 3)
    {
        printf("FROMAT : <interface> <proto>\n");
        exit(EXIT_FAILURE);
    }

    char *filter_proto = av[2];

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    struct ifreq iface_req;
    struct sockaddr_ll socket_address;

    memset(&iface_req, 0, sizeof(iface_req));
    memset(&socket_address, 0, sizeof(socket_address));

    strncpy(iface_req.ifr_name, av[1], IF_NAMESIZE - 1);

    if (sock == -1)
    {
        perror("ERROR ! (socket)");
        exit(EXIT_FAILURE);
    }
    
    int agent_hardware = ioctl(sock, SIOCGIFINDEX, &iface_req);

    if (agent_hardware == -1)
    {
        perror("ERROR ! (ioct1)");
        exit(EXIT_FAILURE);
    }

    int ifindex = iface_req.ifr_ifindex;

    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_ifindex = ifindex;

    int connect_sock = bind(sock, (struct sockaddr *)&socket_address, sizeof(socket_address));

    if (connect_sock == -1)
    {
        printf("ERROR ! (bind)");
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[65535];    
    
    while (1)
    {
        int bytes_received = recvfrom(sock, buffer,
                                     sizeof(buffer), 0, NULL, NULL);

        if (bytes_received == -1)
        {
            perror("ERROR ! (recvfrom)");
            continue;
        }

        struct ether_header *eth = (struct ether_header *)buffer; 
        uint16_t eth_type = ntohs(eth->ether_type);

        if (eth_type != ETH_P_IP)
        {
            continue;
        }

        struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ether_header));
        int ip_header_length = ip_header->ihl * 4;
        unsigned char *transport = buffer + sizeof(struct ether_header) + ip_header_length;
        struct in_addr src_ip;
        struct in_addr dst_ip;
        
        uint8_t proto = ip_header->protocol;

        src_ip.s_addr = ip_header->saddr;
        dst_ip.s_addr = ip_header->daddr;

        uint16_t src_port = 0;
        uint16_t dst_port = 0;

        if (strcmp(filter_proto, "tcp") == 0 && proto != 6)
            continue;
        else if (strcmp(filter_proto, "udp") == 0 && proto != 17)
            continue;
        else if (strcmp(filter_proto, "icmp") == 0 && proto != 1)
            continue;

        if (proto == 6)
        {
            struct tcphdr *tcp = (struct tcphdr *)transport;
            src_port = ntohs(tcp->source);
            dst_port = ntohs(tcp->dest);
        }

        else if (proto == 17)
        {
            struct udphdr *udp = (struct udphdr *)transport;
            src_port = ntohs(udp->source);
            dst_port = ntohs(udp->dest);
        }

        if (proto == 6)
        {
                printf(GREEN "[IP] %s:%d -> %s:%d | protocole=TCP(%d)  | len=%d\n" RESET,
                    inet_ntoa(src_ip), src_port, 
                    inet_ntoa(dst_ip), dst_port,
                    proto,
                    bytes_received);
        }

        else if (proto == 17)
        {
                 printf(GREEN "[IP] %s:%d -> %s:%d | protocole=UDP(%d)  | len=%d\n" RESET,
                    inet_ntoa(src_ip), src_port, 
                    inet_ntoa(dst_ip), dst_port,
                    proto,
                    bytes_received);           
        }

        else if (proto == 1)
        {
            printf(GREEN "[IP] %s -> %s | protocole=ICMP(%d) | len=%d\n" RESET,
                    inet_ntoa(src_ip),
                    inet_ntoa(dst_ip),
                    proto,
                    bytes_received);
        }

        else
        {
                printf(GREEN "[IP] %s -> %s | protocole=%d | len=%d\n" RESET,
                    inet_ntoa(src_ip), 
                    inet_ntoa(dst_ip), 
                    proto,
                    bytes_received);
        }

        int ethernet_size  = sizeof(struct ether_header);
        int ip_size        = ip_header_length;
        int transport_size = 0;

        if (proto == 6)
        {
            struct tcphdr *tcp2 = (struct tcphdr *)transport;
            transport_size = tcp2->doff * 4;
        }

        else if (proto == 17)
        {
            transport_size = sizeof(struct udphdr);
        }

        else
        {
            transport_size = 0;
        }

        int header_total = ethernet_size + ip_size + transport_size;

        if (header_total >= bytes_received)
        {
            continue; // pas de payload
        }

        unsigned char *payload = buffer + header_total;
        int payload_len = bytes_received - header_total;

        if (payload_len > 0)
        {
            int max_dump = 32;

            printf("[HEX]  ");

            for (int i = 0; i < payload_len && i < max_dump; i++)
            {
                printf("%02x ", payload[i]);
            }

            printf("\n");

            printf("[ASCII]  ");
            for (int i = 0; i < payload_len && i < max_dump; i++)
            {
                unsigned char c = payload[i];
                if (c >= 32 && c <= 126)
                    printf("%c", c);
                else
                    printf(".");
            }
            printf("\n\n");
            
        }

    }

}