#include "config.h"

const char *g_capture_interface;
const char *g_server_interface;

static cfg_t *cfg;
static cfg_opt_t cfg_opts[] = {
	CFG_STR("capture_interface", "", CFGF_NONE),
	CFG_STR("server_interface", "", CFGF_NONE),
	CFG_END()
};

/**
 * 初始化config模块
 * 加载配置文件中的配置项至全局变量中
 */
void
WD_config_init()
{
	cfg = cfg_init(cfg_opts, CFGF_NONE);
	if(cfg_parse(cfg, WD_CONF_PATH) == CFG_PARSE_ERROR) {
		user_exit1("config file %s parse error", WD_CONF_PATH);
	}
	g_capture_interface = cfg_getstr(cfg, "capture_interface");
	g_server_interface = cfg_getstr(cfg, "server_interface");
}
