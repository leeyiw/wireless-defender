CC = gcc
CFLAGS = -c
DEBUG_FLAGS = -g -Wall -DWD_DEBUG
SRC = src/

TARGET = wireless-defender

.PHONY: debug all clean

debug: CFLAGS += $(DEBUG_FLAGS)
debug: all

all: wireless-defender.o capture.o analyse.o config.o utils.o
	$(CC) -o $(TARGET) *.o -lpcap -lconfuse
wireless-defender.o: $(SRC)wireless-defender.c $(SRC)wireless-defender.h
	$(CC) $(CFLAGS) $(SRC)wireless-defender.c
capture.o: $(SRC)capture.c $(SRC)capture.h
	$(CC) $(CFLAGS) $(SRC)capture.c
analyse.o: $(SRC)analyse.c $(SRC)analyse.h
	$(CC) $(CFLAGS) $(SRC)analyse.c
config.o: $(SRC)config.c $(SRC)config.h
	$(CC) $(CFLAGS) $(SRC)config.c
utils.o: $(SRC)utils.c $(SRC)utils.h
	$(CC) $(CFLAGS) $(SRC)utils.c

clean:
	-rm *.o $(TARGET)
