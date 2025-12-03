#ifndef POISONING_H
#define POISONING_H

#include <netinet/in.h>
#include <net/if.h>
void *poison_thread(void *arg);

#endif

typedef struct mitm_ctx
{
    char iface[IF_NAMESIZE];
    unsigned char attacker_mac[6];
    unsigned char victim_mac[6];
    unsigned char gateway_mac[6];
    struct in_addr victim_ip;
    struct in_addr gateway_ip;
    int raw_sock;
    int if_index;
}mitm_ctx; 



