#ifndef _UTILS_H
#define _UTILS_H

#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#define BUF_LEN			65536

#ifdef WD_DEBUG
#define DEBUG_INFO(s) printf s
#else
#define DEBUG_INFO(s)
#endif

extern void user_info(const char *str);
extern void user_info1(const char *format, ...);
extern void user_exit(const char *str);
extern void user_exit1(const char *format, ...);
extern void err_exit(const char *str);
extern void err_exit1(const char *format, ...);

#endif
