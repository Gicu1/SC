CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

crypto: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

clean:
	rm -f $(OBJ) crypto
