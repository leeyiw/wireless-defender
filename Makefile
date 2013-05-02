CC = gcc
CFLAGS = -c
DEBUG_FLAGS = -g -Wall -DWD_DEBUG
SRC = src/

TARGET = wireless-defender
OBJ = wireless-defender.o analyse.o analyse_manage.o analyse_control.o\
      analyse_data.o wdcp.o server.o capture.o config.o utils.o

.PHONY: debug dump offline all clean

debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean all

dump: CFLAGS += -DWD_DUMP
dump: clean debug

offline: CFLAGS += -DWD_OFFLINE
offline: clean debug

all: $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) -lpcap -lconfuse -lssl -lcrypto
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
analyse_manage.o: analyse_manage.c analyse_manage.h
	$(CC) $(CFLAGS) analyse_manage.c
analyse_control.o: analyse_control.c analyse_control.h
	$(CC) $(CFLAGS) analyse_control.c
analyse_data.o: analyse_data.c analyse_data.h
	$(CC) $(CFLAGS) analyse_data.c
config.o: config.c config.h
	$(CC) $(CFLAGS) config.c
utils.o: utils.c utils.h
	$(CC) $(CFLAGS) utils.c

clean:
	-rm *.o $(TARGET)
