#include <libubox/blobmsg.h>
#include "ubus_debug.h"
#include <stdio.h>

static int init = 0;
static void *cookie = NULL;
static struct blob_buf b;

void wpa_ubus_error_init()
{
	init = 1;
}
/* Store error logs in buffer for further usage */
void wpa_ubus_error_msg(const char *fmt, va_list ap)
{
	if (!init)
		return;
	wpa_ubus_error_reset(1);
	blobmsg_vprintf(&b, NULL, fmt, ap);
}
void wpa_ubus_error_reset(int errors)
{
	if (!init)
		return;
	if (errors && cookie != NULL) {
		return;
	}
	blobmsg_buf_init(&b);
	cookie = NULL;
	if (errors)
		cookie = blobmsg_open_array(&b, "errors");
}
void wpa_ubus_error_close()
{
	if (!init)
		return;
	if (cookie != NULL) {
		blobmsg_close_array(&b, cookie);
		cookie = NULL;
	}
}
void *wpa_ubus_error_blob()
{
	if (!init)
		return NULL;
	return &b;
}
