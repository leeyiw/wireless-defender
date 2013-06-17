#ifndef _LOG_H_
#define _LOG_H_

/* 日志级别 */
#define LOG_FATAL	(4)
#define LOG_ERROR	(3)
#define LOG_WARN	(2)
#define LOG_INFO	(1)
#define LOG_DEBUG	(0)

#define WD_LOG_PATH "wireless-defender.log"

/**
 * 初始化日志模块
 */
extern void WD_log_init();

/**
 * 结束日志记录
 */
extern void WD_log_final();

/**
 * 记录调试信息，程序可以继续执行
 * @param format 格式化字符串
 * @param 可变的填充格式化字符串使用的参数
 */
extern void WD_log_debug(const char *format, ...);

/**
 * 记录普通信息，程序可以继续执行
 * @param format 格式化字符串
 * @param 可变的填充格式化字符串使用的参数
 */
extern void WD_log_info(const char *format, ...);

/**
 * 记录警告信息，程序可以继续执行
 * @param format 格式化字符串
 * @param 可变的填充格式化字符串使用的参数
 */
extern void WD_log_warn(const char *format, ...);

/**
 * 记录错误，记录后就错误退出
 * @param format 格式化字符串
 * @param 可变的填充格式化字符串使用的参数
 */
extern void WD_log_error(const char *format, ...);

/**
 * 记录致命错误，记录后就错误退出
 * @param format 格式化字符串
 * @param 可变的填充格式化字符串使用的参数
 */
extern void WD_log_fatal(const char *format, ...);

#endif
