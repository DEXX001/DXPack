CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -g
LDFLAGS = -lpthread

SRC = main.c poisoning.c sniffer.c routing.c utils.c
OBJ = $(SRC:.c=.o)

NAME = dxp_mitm

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(OBJ) -o $(NAME) $(LDFLAGS)

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
