#include "wireless-defender.h"

int main(int argc, char *argv[])
{
	WD_config_init();

	DEBUG_INFO(("%s\n", g_interface));
	return 0;
}
