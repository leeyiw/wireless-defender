#ifndef _CONFIG_H
#define _CONFIG_H

#include <confuse.h>

#include "utils.h"

#define WD_CONF_PATH "wireless-defender.conf"

extern void WD_config_init();

extern const char *g_interface;

#endif
