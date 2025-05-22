CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -O2
LDLIBS  = -lgmp

SRC     = $(wildcard src/*.c)
OBJ     = $(SRC:.c=.o)

crypto: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

clean:
	rm -f $(OBJ) crypto
