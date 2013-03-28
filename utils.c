#include "utils.h"

void
user_info(const char *str)
{
	fprintf(stdout, "%s\n", str);
}

void
user_info1(const char *format, ...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, format);
	vsprintf(buf, format, ap);
	fprintf(stdout, "%s\n", buf);
	va_end(ap);
}

void
user_exit(const char *str)
{
	fprintf(stderr, "%s\n", str);
	exit(EXIT_FAILURE);
}

void
user_exit1(const char *format, ...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, format);
	vsprintf(buf, format, ap);
	fprintf(stderr, "%s\n", buf);
	va_end(ap);
	exit(EXIT_FAILURE);
}

void
err_info(const char *str)
{
	fprintf(stderr, "%s\n", str);
}

void
err_exit(const char *str)
{
	perror(str);
	exit(EXIT_FAILURE);
}

void
err_exit1(const char *format, ...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, format);
	vsprintf(buf, format, ap);
	fprintf(stderr, "%s: %s\n", buf, strerror(errno));
	va_end(ap);
	exit(EXIT_FAILURE);
}
