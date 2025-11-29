#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#define ERROR -1


int main(int ac, char **av)
{
    if (ac != 2)
    {
        printf("ERROR | Respectez le format --> \"0.0.0.0\" \n");
        exit(EXIT_FAILURE);
    } 

    for (int i = 0; i <= 1024; i++)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in target;
        struct timeval timeout;

        timeout.tv_sec = 2; 
        timeout.tv_usec = 0;

        if (sock == ERROR)
            exit(EXIT_FAILURE);

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        target.sin_family = AF_INET;
        target.sin_port = htons(i);
        target.sin_addr.s_addr = inet_addr(av[1]); 
    
        int resultat = connect(sock, (struct sockaddr *)&target, 
                               sizeof(target));

        if (resultat == 0)
        {
            char buffer[2024] = {0};
            int n = recv(sock, buffer, sizeof(buffer), 0);

            if (n > 0)
                printf("-- Port %d OPEN --\n %s", i, buffer);
            else if (n == -1 || n == 0)
                printf("-- Port %d OPEN ( silencieux ) --\n", i);

        }

        close(sock);
    }
    
    return(EXIT_SUCCESS);
}