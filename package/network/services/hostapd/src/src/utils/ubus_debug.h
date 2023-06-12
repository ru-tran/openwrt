#ifndef __UBUS_DEBUG_H
#define __UBUS_DEBUG_H

#include <stdarg.h>

#ifdef UBUS_SUPPORT

void wpa_ubus_error_init();
void wpa_ubus_error_msg(const char *fmt, va_list ap);
void wpa_ubus_error_reset(int errors);
void wpa_ubus_error_close();
void *wpa_ubus_error_blob();

#endif


#endif
