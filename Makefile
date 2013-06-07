CC = gcc
CFLAGS = -c
DEBUG_FLAGS = -g -Wall -DWD_DEBUG
SRC = src/

TARGET = wireless-defender
OBJ = wireless-defender.o analyse.o wdcp.o server.o capture.o config.o \
	  utils.o preprocess.o decrypt.o

.PHONY: debug dump offline all clean

debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean all

dump: CFLAGS += -DWD_DUMP
dump: clean debug

offline: CFLAGS += -DWD_OFFLINE
offline: clean debug

all: $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) -lpcap -lconfuse -lssl -lcrypto -lpthread
wireless-defender.o: wireless-defender.c wireless-defender.h
	$(CC) $(CFLAGS) wireless-defender.c
server.o: server.c server.h
	$(CC) $(CFLAGS) server.c
wdcp.o: wdcp.c wdcp.h
	$(CC) $(CFLAGS) wdcp.c
capture.o: capture.c capture.h
	$(CC) $(CFLAGS) capture.c
analyse.o: analyse.c analyse.h preprocess.h decrypt.h utils.h
	$(CC) $(CFLAGS) analyse.c
preprocess.o: preprocess.c preprocess.h analyse.h utils.h decrypt.h
	$(CC) $(CFLAGS) preprocess.c
decrypt.o: decrypt.c decrypt.h
	$(CC) $(CFLAGS) decrypt.c
config.o: config.c config.h
	$(CC) $(CFLAGS) config.c
utils.o: utils.c utils.h
	$(CC) $(CFLAGS) utils.c

clean:
	-rm *.o $(TARGET)
