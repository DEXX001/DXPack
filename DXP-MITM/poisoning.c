#include "poisoning.h"     // ta struct + prototype
#include <stdio.h>         // printf
#include <stdlib.h>        // EXIT_FAILURE
#include <string.h>        // memcpy
#include <unistd.h>        // usleep / sleep
#include <sys/socket.h>    // sockets raw
#include <arpa/inet.h>     // htons etc.
#include <net/ethernet.h>  // struct ether_header
#include <netinet/if_ether.h> // struct ether_arp
#include <linux/if_packet.h>  // sockaddr_ll

