#include "config.h"

const char *g_interface;

static cfg_t *cfg;
static cfg_opt_t cfg_opts[] = {
	CFG_STR("interface", "", CFGF_NONE),
	CFG_END()
};

/** \brief 初始化config模块，
 *
 * 加载配置文件中的配置项至全局变量中
 */
void
WD_config_init()
{
	cfg = cfg_init(cfg_opts, CFGF_NONE);
	if(cfg_parse(cfg, WD_CONF_PATH) == CFG_PARSE_ERROR) {
		user_exit1("config file %s parse error", WD_CONF_PATH);
	}
	g_interface = cfg_getstr(cfg, "interface");
}
