#ifndef _SERVER_H
#define _SERVER_H

#define WD_SERVER_LISTEN_PORT		9387
#define WD_SERVER_LISTEN_BACKLOG	64

extern void WD_server_start();
extern void WD_server_wait();

#endif
