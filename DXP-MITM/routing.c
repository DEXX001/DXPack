#include <stdio.h>    // perror
#include <stdlib.h>   // exit, EXIT_FAILURE (si tu veux)
#include <fcntl.h>    // open
#include <unistd.h>   // write, close
#include "routing.h"

#include <stdio.h>
#include "utils.h"

void print_banner(void)
{
    printf(
        "=========================================\n"
        "        D X P   M I T M   v0.1\n"
        "        (DXPack - MITM)\n"
        "=========================================\n"
        "\n"
    );
}


void enable_ip_forward(void)
{
    int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
    
    if (fd == -1)
    {
        perror("open ip_forward");
        return;
    }

    int res = write(fd, "1", 1);

    if (res == -1)
    {
        perror("write ip_forward");
        close(fd);
        return;
    }

    close(fd);
}

void disable_rp_filter_all(void)
{
    int fd = open("/proc/sys/net/ipv4/conf/all/rp_filter", O_WRONLY);

    if (fd == -1)
    {
        perror("ERROR ! open rp_filter_all");
        return;
    }

    int res = write(fd, "0", 1);

    if (res == -1)
    {
        perror("ERROR ! write rp_filter_all");
        close(fd);
        return;
    }
    
    close(fd);
}

void disable_rp_filter_iface(const char *iface)
{
    char path[256];

    snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/rp_filter", iface);

    int fd = open(path, O_WRONLY);

    if (fd == -1)
    {
        perror("ERROR ! rp_filter_iface");
        return;
    }

    int res = write(fd, "0", 1);

    if (res == -1)
    {
        perror("ERROR ! rp_filter_iface");
        close(fd);
        return;
    }

    close(fd);
}