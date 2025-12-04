# =========================
#  DXP-MITM - Makefile
# =========================

CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -g
LDFLAGS = -lpthread

NAME    = dxp_mitm

SRCS    = main.c \
          poisoning.c \
          sniffer.c \
          routing.c \
          utils.c

OBJS    = $(SRCS:.c=.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
