CC = gcc
CFLAGS = -c
DEBUG_FLAGS = -g -Wall -DWD_DEBUG
SRC = src/

TARGET = wireless-defender

.PHONY: debug clean

debug: wireless-defender.o config.o utils.o
	$(CC) -o $(TARGET) *.o -lconfuse
wireless-defender.o: $(SRC)wireless-defender.c $(SRC)wireless-defender.h
	$(CC) $(CFLAGS) $(SRC)wireless-defender.c
config.o: $(SRC)config.c $(SRC)config.h
	$(CC) $(CFLAGS) $(SRC)config.c
utils.o: $(SRC)utils.c $(SRC)utils.h
	$(CC) $(CFLAGS) $(SRC)utils.c

clean:
	-rm *.o $(TARGET)
