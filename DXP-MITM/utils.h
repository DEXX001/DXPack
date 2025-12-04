#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <arpa/inet.h>

void print_mac(const unsigned char *mac);
void print_ip(uint32_t ip);
void print_banner(void);

#endif
