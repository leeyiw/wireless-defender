#ifndef _SERVER_H
#define _SERVER_H

#define WD_SERVER_LISTEN_PORT		9387
#define WD_SERVER_LISTEN_BACKLOG	64

extern void WD_server_init();
extern void WD_server_main_loop();

#endif
