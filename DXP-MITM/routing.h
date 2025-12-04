// routing.h
#ifndef ROUTING_H
#define ROUTING_H

void enable_ip_forward(void);
void disable_rp_filter_all(void);
void disable_rp_filter_iface(const char *iface);

#endif


