#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#define ERROR -1

int main(int ac, char **av)
{
    char buffer[65535];
    unsigned char *data;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct ether_header *eth = (struct ether_header *) buffer;
    struct ip *ip_address = (struct ip *)(buffer + sizeof(struct ether_header)); 
    struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip));
    struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip)); 

    if (sock == -1)
    {
        perror("ERROR\n");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        int paquet_recv = recv(sock, buffer, sizeof(buffer), 0);
        printf("Paquet capturé : %d octets \nAdresse MAC --> ", paquet_recv);

        for (int i = 0; i < 6; i++)
        {
            printf("%02x:", eth->ether_shost[i]);
        }

        printf("\nIP source : %s ", inet_ntoa(ip_address->ip_src));

        if (ip_address->ip_p == 6)
        {
            data = (unsigned char *)tcp + (tcp->th_off * 4);
            printf(" || -- Protocol : %d -- || Port SRC : %d || Port DEST : %d", ip_address->ip_p, ntohs(tcp->th_sport), 
                                                                                 ntohs(tcp->th_dport));

            for (int i = 0; i < 20; i++)
            {
                if (data[i] >= 32 && data[i] <= 126)
                    printf("(%c)", data[i]);
            
            }
        }

        else if (ip_address->ip_p == 17)
        {
            data = (unsigned char *)(buffer + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            printf(" || -- Protocol : %d -- || Port SRC : %d || Port DEST : %d", ip_address->ip_p, ntohs(udp->uh_sport), 
                                                                                 ntohs(udp->uh_dport));

            for (int i = 0; i < 20; i++)
            {
                if (data[i] >= 32 && data[i] <= 126)
                {
                    printf(" --> (%c)", data[i]);
                }
                
            }
            
        }

    

        printf("\n");
    }

}