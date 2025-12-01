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
    if (ac != 2)
    {
        printf("FROMAT : <interface>\n");
        exit(EXIT_FAILURE);
    }

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

    unsigned char buffer[2024];
    
    while (1)
    {
        int bytes_received = recvfrom(sock, buffer,
                                     sizeof(buffer), 0, NULL, NULL);

        if (bytes_received == -1)
        {
            perror("ERROR ! (recvfrom)");
            continue;
        }

        printf("Packet reçu : %d octets\n", bytes_received);

    }

    
    


}