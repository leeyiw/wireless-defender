CC = gcc
CFLAGS = -c
DEBUG_FLAGS = -g -Wall -DWD_DEBUG
SRC = src/

TARGET = wireless-defender

.PHONY: debug dump offline all clean

debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean all

dump: CFLAGS += -DWD_DUMP
dump: clean debug

offline: CFLAGS += -DWD_OFFLINE
offline: clean debug

all: wireless-defender.o server.o wdcp.o capture.o analyse.o config.o utils.o
	$(CC) -o $(TARGET) *.o -lpcap -lconfuse
wireless-defender.o: wireless-defender.c wireless-defender.h
	$(CC) $(CFLAGS) wireless-defender.c
server.o: server.c server.h
	$(CC) $(CFLAGS) server.c
wdcp.o: wdcp.c wdcp.h
	$(CC) $(CFLAGS) wdcp.c
capture.o: capture.c capture.h
	$(CC) $(CFLAGS) capture.c
analyse.o: analyse.c analyse.h
	$(CC) $(CFLAGS) analyse.c
config.o: config.c config.h
	$(CC) $(CFLAGS) config.c
utils.o: utils.c utils.h
	$(CC) $(CFLAGS) utils.c

clean:
	-rm *.o $(TARGET)
