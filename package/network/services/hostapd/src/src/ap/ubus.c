/*
 * hostapd / ubus support
 * Copyright (c) 2013, Felix Fietkau <nbd@nbd.name>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/wpabuf.h"
#include "common/ieee802_11_defs.h"
#include "common/hw_features_common.h"
#include "hostapd.h"
#include "neighbor_db.h"
#include "wps_hostapd.h"
#include "sta_info.h"
#include "ubus.h"
#include "ap_drv_ops.h"
#include "beacon.h"
#include "accounting.h"
#include "radius/radius.h"
#include "rrm.h"
#include "wnm_ap.h"
#include "taxonomy.h"
#include "hw_features.h"
#include "common/hw_features_common.h"
#include "airtime_policy.h"
#include "hw_features.h"

#define ACCT_DEFAULT_UPDATE_INTERVAL 300

static struct ubus_context *ctx;
static struct blob_buf b;
static int ctx_ref;

static inline struct hapd_interfaces *get_hapd_interfaces_from_object(struct ubus_object *obj)
{
	return container_of(obj, struct hapd_interfaces, ubus);
}

static inline struct hostapd_data *get_hapd_from_object(struct ubus_object *obj)
{
	return container_of(obj, struct hostapd_data, ubus.obj);
}

struct ubus_banned_client {
	struct avl_node avl;
	u8 addr[ETH_ALEN];
};

static void ubus_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct ubus_context *ctx = eloop_ctx;
	ubus_handle_event(ctx);
}

static void ubus_reconnect_timeout(void *eloop_data, void *user_ctx)
{
	if (ubus_reconnect(ctx, NULL)) {
		eloop_register_timeout(1, 0, ubus_reconnect_timeout, ctx, NULL);
		return;
	}

	eloop_register_read_sock(ctx->sock.fd, ubus_receive, ctx, NULL);
}

static void hostapd_ubus_connection_lost(struct ubus_context *ctx)
{
	eloop_unregister_read_sock(ctx->sock.fd);
	eloop_register_timeout(1, 0, ubus_reconnect_timeout, ctx, NULL);
}

static bool hostapd_ubus_init(void)
{
	if (ctx)
		return true;

	ctx = ubus_connect(NULL);
	if (!ctx)
		return false;

	ctx->connection_lost = hostapd_ubus_connection_lost;
	eloop_register_read_sock(ctx->sock.fd, ubus_receive, ctx, NULL);


	return true;
}

static void hostapd_ubus_ref_inc(void)
{
	ctx_ref++;
}

static void hostapd_ubus_ref_dec(void)
{
	ctx_ref--;
	if (!ctx)
		return;

	if (ctx_ref)
		return;

	eloop_unregister_read_sock(ctx->sock.fd);
	ubus_free(ctx);
	ctx = NULL;
}

static int
hostapd_iface_get_state(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct hostapd_iface *iface = container_of(obj, struct hostapd_iface,
			ubus.obj);

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "state_num", iface->state);
	blobmsg_add_string(&b, "state", hostapd_state_text(iface->state));
	blobmsg_add_u32(&b, "freq", iface->freq);
	if (iface->bss[0] && iface->bss[0]->conf->uci_device)
		blobmsg_add_string(&b, "device", iface->bss[0]->conf->uci_device);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}
static int
hostapd_iface_get_bss(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct hostapd_iface *iface = container_of(obj, struct hostapd_iface,
			ubus.obj);
	struct hostapd_data *bss;
	void *a,*h;
	int i;
	const char *state = hostapd_state_text(iface->state);

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "state_num", iface->state);
	blobmsg_add_string(&b, "state", state);
	blobmsg_add_u32(&b, "freq", iface->freq);
	if (iface->bss[0] && iface->bss[0]->conf->uci_device)
		blobmsg_add_string(&b, "device", iface->bss[0]->conf->uci_device);
	a = blobmsg_open_array(&b, "bss");
	for (i=0; i<iface->num_bss; ++i) {
		bss = iface->bss[i];
		h = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "iface", bss->conf->iface);
		blobmsg_add_string(&b, "state", state);
		if (bss->conf->uci_device)
			blobmsg_add_string(&b, "device", bss->conf->uci_device);
		if (bss->ubus.obj.id)
			blobmsg_add_string(&b, "uobject", bss->ubus.obj.name);
		blobmsg_close_table(&b, h);
	}
	blobmsg_close_array(&b, a);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}


#ifdef NEED_AP_MLME
enum {
	CSA_FREQ,
	CSA_CHANNEL,
	CSA_FREQS,
	CSA_CHANNELS,
	CSA_BCN_COUNT,
	CSA_CENTER_FREQ1,
	CSA_CENTER_FREQ2,
	CSA_BANDWIDTH,
	CSA_SEC_CHANNEL_OFFSET,
	CSA_HT,
	CSA_VHT,
	CSA_SECONDARY_CHANNEL,
	CSA_VHT_OPER_CWIDTH,
	CSA_BLOCK_TX,
	CSA_FAST,
	CSA_ALLOW_ACS,
	__CSA_MAX
};

static const struct blobmsg_policy csa_policy[__CSA_MAX] = {
	[CSA_FREQ] = { "freq", BLOBMSG_TYPE_INT32 },
	[CSA_CHANNEL] = { "channel", BLOBMSG_TYPE_INT32 },
	[CSA_FREQS] = { "freqs", BLOBMSG_TYPE_ARRAY },
	[CSA_CHANNELS] = { "channels", BLOBMSG_TYPE_ARRAY },
	[CSA_BCN_COUNT] = { "bcn_count", BLOBMSG_TYPE_INT32 },
	[CSA_CENTER_FREQ1] = { "center_freq1", BLOBMSG_TYPE_INT32 },
	[CSA_CENTER_FREQ2] = { "center_freq2", BLOBMSG_TYPE_INT32 },
	[CSA_BANDWIDTH] = { "bandwidth", BLOBMSG_TYPE_INT32 },
	[CSA_SEC_CHANNEL_OFFSET] = { "sec_channel_offset", BLOBMSG_TYPE_INT32 },
	[CSA_HT] = { "ht", BLOBMSG_TYPE_BOOL },
	[CSA_VHT] = { "vht", BLOBMSG_TYPE_BOOL },
	[CSA_SECONDARY_CHANNEL] = { "secondary_channel", BLOBMSG_TYPE_INT32 },
	[CSA_VHT_OPER_CWIDTH] = { "vht_oper_chwidth", BLOBMSG_TYPE_INT32 },
	[CSA_BCN_COUNT] = { "bcn_count", BLOBMSG_TYPE_INT32 },
	[CSA_BLOCK_TX] = { "block_tx", BLOBMSG_TYPE_BOOL },
	[CSA_FAST] = { "fast", BLOBMSG_TYPE_BOOL },
	[CSA_ALLOW_ACS] = { "allow_acs", BLOBMSG_TYPE_BOOL },
};

static void ubus_adjust_vht_center_freq(struct hostapd_iface *iface,
				       int chan, int secondary_channel, int *vht_oper_chwidth,
					   int ht, int vht,
				       u8 *vht_oper_centr_freq_seg0_idx,
				       u8 *vht_oper_centr_freq_seg1_idx)
{
	*vht_oper_centr_freq_seg1_idx = 0;
	if (!chan)
		return;
	if (!ht && !vht) {
		*vht_oper_chwidth = CHANWIDTH_USE_HT;
		*vht_oper_centr_freq_seg0_idx = chan;
		return;
	}

	switch (*vht_oper_chwidth) {
	case CHANWIDTH_USE_HT:
	case 40:
		*vht_oper_chwidth = CHANWIDTH_USE_HT;
		if (secondary_channel == 1)
			*vht_oper_centr_freq_seg0_idx = chan + 2;
		else if (secondary_channel == -1)
			*vht_oper_centr_freq_seg0_idx = chan - 2;
		else
			*vht_oper_centr_freq_seg0_idx = chan;
		break;
	case CHANWIDTH_80MHZ:
	case 80:
		*vht_oper_chwidth = CHANWIDTH_80MHZ;
		*vht_oper_centr_freq_seg0_idx = chan + 6;
		break;
	case CHANWIDTH_160MHZ:
	case 160:
		*vht_oper_chwidth = CHANWIDTH_160MHZ;
		*vht_oper_centr_freq_seg0_idx = chan + 14;
		break;
	case 20:
	default:
		*vht_oper_chwidth = CHANWIDTH_USE_HT;
		*vht_oper_centr_freq_seg0_idx = chan;
		break;
	}
}
static int ubus_bandwidth_to_vht_oper_chwidth(int bandwidth, int center_freq1,
			int center_freq2)
{
	if (bandwidth < 80) {
		return CHANWIDTH_USE_HT;
	} else if (bandwidth < 160) {
		return center_freq2 ? CHANWIDTH_80P80MHZ : CHANWIDTH_80MHZ;
	} else {
		return CHANWIDTH_160MHZ;
	}
}

static int
hostapd_iface_try_channel_fallback_helper(struct hostapd_iface *iface,
		struct wpa_freq_range_list *ch_list, int ht, int vht, int sec_channel,
		int vht_oper_chwidth, int center_idx0, int center_idx1, int acs,
		int *disabled, int do_switch)
{
	iface->conf->ieee80211n = ht;
	iface->conf->ieee80211ac = vht;
    iface->conf->secondary_channel = sec_channel;
	//iface->freq = ch_list->range->min;
	iface->conf->channel = ch_list->range->min;
	iface->conf->vht_oper_centr_freq_seg0_idx = center_idx0;
	iface->conf->vht_oper_centr_freq_seg1_idx = center_idx1;
	iface->conf->vht_oper_chwidth = vht_oper_chwidth;
	iface->conf->acs = acs;
	if (acs)
		iface->conf->channel = 0;
	wpa_printf(MSG_DEBUG, "ubus: Fallback channel switch selected %d - %s, "
			"list: %s, ht - %d, vht - %d sec_channel - %d, seg0_idx - %d, "
			"seg1_idx - %d, chwidth - %d", iface->conf->channel,
			acs ? "with acs" : "without acs", freq_range_list_str(ch_list), ht,
			vht, sec_channel, center_idx0, center_idx1, vht_oper_chwidth);
	iface->conf->acs_ch_list.range =
		os_realloc_array(iface->conf->acs_ch_list.range, ch_list->num,
			sizeof(struct wpa_freq_range));
	os_memcpy (iface->conf->acs_ch_list.range, ch_list->range,
			ch_list->num * 	sizeof(struct wpa_freq_range));
	iface->conf->acs_ch_list.num = ch_list->num;

	if (!*disabled) {
		if (!do_switch) {
			return 0;
		}
		hostapd_disable_iface(iface);
		*disabled = 1;
	}
	if (!hostapd_enable_iface(iface)) {
		*disabled = 0;
		return 0;
	}
	return -1;
}
static int
hostapd_iface_try_channel_fallback(struct hostapd_iface *iface,
		struct wpa_freq_range_list *ch_list, int ht, int vht, int sec_channel,
		int vht_oper_chwidth, int acs, int *disabled, int do_switch)
{
	u8 center_idx0, center_idx1;
	ubus_adjust_vht_center_freq(iface, ch_list->range->min, sec_channel,
			&vht_oper_chwidth, ht, vht, &center_idx0,  &center_idx1);

	return hostapd_iface_try_channel_fallback_helper(iface, ch_list, ht, vht,
			sec_channel, vht_oper_chwidth, center_idx0, center_idx1, acs,
			disabled, do_switch);
}
static int
hostapd_iface_try_channel_fallback_fp(struct hostapd_iface *iface,
		struct hostapd_freq_params *data, int acs,
		struct wpa_freq_range_list *ch_list, int *disabled, int do_switch)
{
	int center_idx0 = hostapd_hw_get_channel(iface->bss[0], data->center_freq1);
	int center_idx1 = hostapd_hw_get_channel(iface->bss[0], data->center_freq2);

	return hostapd_iface_try_channel_fallback_helper(iface, ch_list,
			data->ht_enabled, data->vht_enabled,
			data->sec_channel_offset,
			ubus_bandwidth_to_vht_oper_chwidth(data->bandwidth,
				center_idx0, center_idx1), center_idx0, center_idx1,
			acs, disabled, do_switch);
}
static int hostapd_set_curr_freq_params(struct hostapd_iface *iface,
		struct hostapd_freq_params *params, int *acs,
		struct wpa_freq_range_list *ch_list)
{
	struct hostapd_config *conf = iface->conf;
	struct he_capabilities *he_cap = NULL;
	memset(params, 0, sizeof(*params));
	memset(ch_list, 0, sizeof(*ch_list));

	if (hostapd_set_freq_params(params,
				conf->hw_mode,
				hostapd_hw_get_freq(*iface->bss, conf->channel),
				conf->channel,
				0,0, 
				conf->ieee80211n,
				conf->ieee80211ac,
				0,
				conf->secondary_channel,
				conf->vht_oper_chwidth,
				conf->vht_oper_centr_freq_seg0_idx,
				conf->vht_oper_centr_freq_seg1_idx,
				conf->vht_capab,
				he_cap 
			))
    {
            params->channel = 0;
			return -1;
    }
	*acs = conf->acs;
	if (!*acs)
		return 0;
	ch_list->range = os_calloc(conf->acs_ch_list.num, sizeof(*ch_list->range));
	ch_list->num = conf->acs_ch_list.num;
	os_memcpy(ch_list->range, conf->acs_ch_list.range,
			conf->acs_ch_list.num * sizeof(*ch_list->range));
    return 0;
}
static int
hostapd_freq_params_compare(struct hostapd_freq_params *a,
		struct hostapd_freq_params *b)
{
	/* Compiler could choose different size of enum than int. Other values are
	 * the same size, so there should not be any padding */
	return a->mode == b->mode &&
		os_memcmp(&a->freq, &b->freq, sizeof(*a) - ((void *)&a->freq - (void *)a)) == 0;
}

static int
hostapd_iface_try_channel(struct hostapd_iface *iface, struct hostapd_freq_params *old,
		struct wpa_freq_range_list *ch_list, int ht, int vht, int sec_channel,
		int vht_oper_chwidth, int cs_count, int block_tx, int fast,
		int acs, int *disabled)
{
	struct csa_settings css;
	struct hostapd_freq_params *freq_params = &css.freq_params;
	struct he_capabilities *he_cap = NULL;
	unsigned int i, k;
	int err = 1;
	int chan, freq;
	u8 center_idx0, center_idx1;

	memset(&css, 0, sizeof (css));
	css.cs_count = cs_count;
	css.block_tx = block_tx;

	if (*disabled) {
		return hostapd_iface_try_channel_fallback(iface, ch_list, ht, vht,
				sec_channel, vht_oper_chwidth, acs, disabled, 1);
	}
	if (hostapd_csa_in_progress(iface) || iface->cac_started)
		return -1;
	if (iface->state != HAPD_IFACE_ENABLED) {
		return hostapd_iface_try_channel_fallback(iface, ch_list, ht, vht,
				sec_channel, vht_oper_chwidth, acs, disabled, 1);
	}

	for (i=0; i < ch_list->num; ++i) {
		/*
		 * Allow selection of DFS channel in ETSI to comply with
		 * uniform spreading.
		 */
		chan = ch_list->range[i].min;
		freq = hostapd_hw_get_freq(iface->bss[0], chan);
		ubus_adjust_vht_center_freq(iface, chan, sec_channel, &vht_oper_chwidth,
				ht, vht, &center_idx0, &center_idx1);

		if (hostapd_set_freq_params(freq_params, iface->conf->hw_mode,
					freq, chan,	0,0, ht, vht, 0, sec_channel, vht_oper_chwidth,
					center_idx0, center_idx1,
					iface->current_mode->vht_capab,
					he_cap))
		{
			wpa_printf(MSG_WARNING, "Can not build channel freq=%d, chan=%d, "
					"ht=%d, vht=%d, sec_channel=%d, vht_cwidth=%d, center0=%d, "
					"center1=%d", freq, chan,
					ht, vht, sec_channel, vht_oper_chwidth,
					center_idx0, center_idx1);
			return UBUS_STATUS_INVALID_ARGUMENT;
		}
		if (hostapd_freq_params_compare(old, freq_params)) {
			return 0;
		}

		/* Perform channel switch/CSA */
		for (k = 0; k < iface->num_bss; k++) {
			err = hostapd_switch_channel(iface->bss[k], &css);
			if (err)
				break;
		}
		if (!err) {
			/* Set configuration to selected channel */
			ch_list->range[i].min = ch_list->range[i].max = ch_list->range->min;
			ch_list->range->min = ch_list->range->max = chan;
			return hostapd_iface_try_channel_fallback(iface, ch_list, ht, vht,
				sec_channel, vht_oper_chwidth, acs, disabled, 0);
		} else if (!fast) {
			/* In slow mode try only first channel for switch. Others - for
			 * ACS and DFS procedures */
			break;
		}
	}
	if (fast)
		return -1;
	wpa_printf(MSG_DEBUG, "Can not perform fast switch. Use fallback method");
	return hostapd_iface_try_channel_fallback(iface, ch_list, ht, vht,
			sec_channel, vht_oper_chwidth, acs, disabled, 1);
}
static int ubus_check_channel(struct hostapd_iface *iface, int n)
{
	struct hostapd_channel_data *chan =
		hw_get_channel_chan(iface->current_mode, n, NULL);

	if (!chan) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (chan->flag & HOSTAPD_CHAN_DISABLED) {
		return UBUS_STATUS_NOT_SUPPORTED;
	}
	return 0;
}
static int blobmsg_get_ch_list(struct blob_attr *attr, struct hostapd_iface *iface,
		struct wpa_freq_range_list *ch_list, int is_array, int is_channel)
{
	int val;
	struct blob_attr *cur;
	int rem;
	int res = 0;

	memset(ch_list, 0, sizeof(*ch_list));
	if (!is_array) {
		ch_list->range = os_calloc(1, sizeof(ch_list->range[0]));
		val = blobmsg_get_u32(attr);
		if (!is_channel)
			val = hostapd_hw_get_channel(iface->bss[0], val);
		ch_list->range->min = ch_list->range->max = val;
		ch_list->num=1;
		res = ubus_check_channel(iface, val);
	} else blobmsg_for_each_attr(cur, attr, rem) {
		ch_list->range = os_realloc_array(ch_list->range, ch_list->num + 1,
				sizeof(ch_list->range[0]));
		val = blobmsg_get_u32(cur);
		ch_list->range[ch_list->num].min = ch_list->range[ch_list->num].max =
			is_channel ? val : hostapd_hw_get_channel(iface->bss[0], val);
		++ch_list->num;
		res = ubus_check_channel(iface, val);
		if (res)
			break;
	}
	if (!res)
		return 0;

	os_free(ch_list->range);
	ch_list->range = NULL;
	ch_list->num=0;
	return res;
}
static int
hostapd_do_switch_chan(struct hostapd_iface *iface, struct blob_attr *tb[],
		struct hostapd_freq_params *old, int cs_count, int block_tx, int fast,
		int acs, int *disabled)
{
	struct wpa_freq_range_list ch_list;
	int ht = old->ht_enabled;
	int vht = old->vht_enabled;
	int sec_channel = old->sec_channel_offset;
	int vht_oper_chwidth = ubus_bandwidth_to_vht_oper_chwidth(old->bandwidth,
			old->center_freq1, old->center_freq2);
	int res = 1;

	if (tb[CSA_FREQ]) {
		res = blobmsg_get_ch_list(tb[CSA_FREQ], iface, &ch_list, 0, 0);
	} else if (tb[CSA_CHANNEL]) {
		res = blobmsg_get_ch_list(tb[CSA_CHANNEL], iface, &ch_list, 0, 1);
	} else if (tb[CSA_FREQS]) {
		res = blobmsg_get_ch_list(tb[CSA_FREQS], iface, &ch_list, 1, 0);
	} else if (tb[CSA_CHANNELS]) {
		res = blobmsg_get_ch_list(tb[CSA_CHANNELS], iface, &ch_list, 1, 1);
	}
	if (res)
		return res;

	if (tb[CSA_HT])
		ht = blobmsg_get_bool(tb[CSA_HT]);
	if (tb[CSA_VHT])
		vht = blobmsg_get_bool(tb[CSA_VHT]);
	if (tb[CSA_SECONDARY_CHANNEL])
		sec_channel = blobmsg_get_u32(tb[CSA_SECONDARY_CHANNEL]);
	if (tb[CSA_VHT_OPER_CWIDTH])
		vht_oper_chwidth = blobmsg_get_u32(tb[CSA_VHT_OPER_CWIDTH]);
	if (tb[CSA_BCN_COUNT])
		cs_count = blobmsg_get_u32(tb[CSA_BCN_COUNT]);
	if (tb[CSA_BLOCK_TX])
		block_tx = blobmsg_get_bool(tb[CSA_BCN_COUNT]);
	if (tb[CSA_FAST])
		fast = blobmsg_get_bool(tb[CSA_FAST]);
	if (tb[CSA_ALLOW_ACS])
		acs = blobmsg_get_bool(tb[CSA_ALLOW_ACS]);
	return hostapd_iface_try_channel(iface, old, &ch_list, ht, vht, sec_channel,
			vht_oper_chwidth, cs_count, block_tx, fast, acs, disabled);
}

static int
hostapd_switch_chan(struct hostapd_data *hapd, struct blob_attr *msg)
{
	struct blob_attr *tb[__CSA_MAX];
	struct csa_settings css;

	blobmsg_parse(csa_policy, __CSA_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[CSA_FREQ])
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(&css, 0, sizeof(css));
	css.freq_params.freq = blobmsg_get_u32(tb[CSA_FREQ]);

#define SET_CSA_SETTING(name, field, type) \
	do { \
		if (tb[name]) \
			css.field = blobmsg_get_ ## type(tb[name]); \
	} while(0)

	SET_CSA_SETTING(CSA_BCN_COUNT, cs_count, u32);
	SET_CSA_SETTING(CSA_CENTER_FREQ1, freq_params.center_freq1, u32);
	SET_CSA_SETTING(CSA_CENTER_FREQ2, freq_params.center_freq2, u32);
	SET_CSA_SETTING(CSA_BANDWIDTH, freq_params.bandwidth, u32);
	SET_CSA_SETTING(CSA_SEC_CHANNEL_OFFSET, freq_params.sec_channel_offset, u32);
	SET_CSA_SETTING(CSA_HT, freq_params.ht_enabled, bool);
	SET_CSA_SETTING(CSA_VHT, freq_params.vht_enabled, bool);
	SET_CSA_SETTING(CSA_BLOCK_TX, block_tx, bool);


	if (hostapd_switch_channel(hapd, &css) != 0)
		return UBUS_STATUS_NOT_SUPPORTED;
	return UBUS_STATUS_OK;
#undef SET_CSA_SETTING
}

static int
hostapd_iface_switch_chan(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct hostapd_iface *iface = container_of(obj, struct hostapd_iface,
			ubus.obj);
	if (iface && iface->bss[0])
		return hostapd_switch_chan(iface, msg);
	return UBUS_STATUS_INVALID_ARGUMENT;
}
enum {
	CSA_LIST,
	CSA_LIST_BCN_COUNT,
	CSA_LIST_BLOCK_TX,
	CSA_LIST_FAST,
	CSA_LIST_ALLOW_ACS,
	__CSA_LIST_MAX,
};
static const struct blobmsg_policy csa_list_policy[__CSA_LIST_MAX] = {
	[CSA_LIST] = { "list", BLOBMSG_TYPE_ARRAY },
	[CSA_LIST_BCN_COUNT] = { "bcn_count", BLOBMSG_TYPE_INT32 },
	[CSA_LIST_BLOCK_TX] = { "block_tx", BLOBMSG_TYPE_BOOL },
	[CSA_LIST_FAST] = { "fast", BLOBMSG_TYPE_BOOL },
	[CSA_LIST_ALLOW_ACS] = { "allow_acs", BLOBMSG_TYPE_BOOL },
};

static int
hostapd_switch_chan_list(struct hostapd_iface *iface, struct blob_attr *msg)
{
	struct blob_attr *tb_l[__CSA_LIST_MAX];
	struct blob_attr *tb[__CSA_MAX];
	struct blob_attr *cur;
	struct hostapd_freq_params old;
	struct wpa_freq_range_list old_ch_list;
	int old_acs;
	int cs_count = 5, block_tx = 0, fast = 0, acs = 0;
	int disabled = iface->state == HAPD_IFACE_DISABLED;
	int rem;
	int err = UBUS_STATUS_OK;

	blobmsg_parse(csa_list_policy, __CSA_LIST_MAX, tb_l,
			blob_data(msg), blob_len(msg));

	if (!tb_l[CSA_LIST])
		return UBUS_STATUS_INVALID_ARGUMENT;

	hostapd_set_curr_freq_params(iface, &old, &old_acs, &old_ch_list);

	if (tb_l[CSA_LIST_BCN_COUNT])
		cs_count = blobmsg_get_u32(tb_l[CSA_LIST_BCN_COUNT]);
	if (tb_l[CSA_LIST_BLOCK_TX])
		block_tx = blobmsg_get_bool(tb_l[CSA_LIST_BCN_COUNT]);
	if (tb_l[CSA_LIST_FAST])
		fast = blobmsg_get_bool(tb_l[CSA_LIST_FAST]);
	if (tb_l[CSA_LIST_ALLOW_ACS])
		acs = blobmsg_get_bool(tb_l[CSA_LIST_ALLOW_ACS]);

	blobmsg_for_each_attr(cur, tb_l[CSA_LIST], rem) {
		blobmsg_parse(csa_policy, __CSA_MAX, tb, blobmsg_data(cur),
				blobmsg_data_len(cur));
		err = hostapd_do_switch_chan(iface, tb, &old, cs_count, block_tx, fast,
				acs, &disabled);
		if (!err)
			goto result;
	}

	if (err < 0)
		err = UBUS_STATUS_NOT_SUPPORTED;
	if (!disabled)
		goto result;

	hostapd_iface_try_channel_fallback_fp(iface, &old, old_acs, &old_ch_list,
			&disabled, 1);
result:
	os_free(old_ch_list.range);
	return err;
}
static int
hostapd_iface_switch_chan_list(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct hostapd_iface *iface = container_of(obj, struct hostapd_iface,
			ubus.obj);
	if (iface && iface->bss[0])
		return hostapd_switch_chan_list(iface, msg);
	return UBUS_STATUS_INVALID_ARGUMENT;
}
#endif

enum {
	STA_ACCOUNT_ADDR,
	__STA_ACCOUNT_MAX,
};

static const struct blobmsg_policy sta_account_policy[__STA_ACCOUNT_MAX] = {
	[STA_ACCOUNT_ADDR] = { "addr", BLOBMSG_TYPE_STRING },
};
static void
blobmsg_add_station_accounting(struct blob_buf *buf,
		const char *name,
		struct sta_info *sta,
		const struct hostap_sta_driver_data *data,
		const struct os_reltime *session_time,
		int cause);
static void blobmsg_add_hapd_id(struct blob_buf *buf, struct hostapd_data *hapd);
static int
hostapd_iface_get_station_account(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct hostapd_iface *iface = container_of(obj, struct hostapd_iface,
			ubus.obj);
	struct hostapd_data *bss = NULL;
	size_t i;
	struct sta_info *sta = NULL;
	u8 addr[ETH_ALEN];
	struct blob_attr *tb[__STA_ACCOUNT_MAX];

	blobmsg_parse(sta_account_policy, __STA_ACCOUNT_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[STA_ACCOUNT_ADDR])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (hwaddr_aton(blobmsg_data(tb[STA_ACCOUNT_ADDR]), addr))
		return UBUS_STATUS_INVALID_ARGUMENT;

	for (i=0; i<iface->num_bss; ++i) {
		bss = iface->bss[i];
		sta = ap_get_sta(bss, addr);
		if (sta != NULL) {
			break;
		}
	}
	if (sta == NULL) {
		return UBUS_STATUS_NOT_FOUND;
	}
	blob_buf_init(&b, 0);
	blobmsg_add_station_accounting(&b, "station", sta, NULL,  NULL, 0);
	blobmsg_add_hapd_id(&b, bss);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static const struct ubus_method iface_methods[] = {
	UBUS_METHOD_NOARG("get_state", hostapd_iface_get_state),
	UBUS_METHOD_NOARG("get_bss", hostapd_iface_get_bss),
	#ifdef NEED_AP_MLME
		UBUS_METHOD("switch_chan", hostapd_iface_switch_chan, csa_policy),
		UBUS_METHOD("switch_chan_list", hostapd_iface_switch_chan_list,
			csa_list_policy),
	#endif
	UBUS_METHOD("get_client_account", hostapd_iface_get_station_account, sta_account_policy),
};
static struct ubus_object_type iface_object_type =
	UBUS_OBJECT_TYPE("hostapd_iface", iface_methods);

void hostapd_ubus_add_iface(struct hostapd_iface *iface)
{

	struct ubus_object *obj = &iface->ubus.obj;
	char *name, *ifname = NULL;
	int ret;

	if (!hostapd_ubus_init())
		return;

	if (obj->id)
		return;

	if (iface->bss[0] && iface->bss[0]->conf->uci_device)
		ifname = iface->bss[0]->conf->uci_device;
	else
		ifname = iface->phy;

	if (asprintf(&name, "hostapd_iface.%s", ifname) < 0)
		return;

	obj->name = name;
	obj->type = &iface_object_type;
	obj->methods = iface_object_type.methods;
	obj->n_methods = iface_object_type.n_methods;

	ret = ubus_add_object(ctx, obj);

	hostapd_ubus_ref_inc();
}

void hostapd_ubus_free_iface(struct hostapd_iface *iface)
{
	struct ubus_object *obj = &iface->ubus.obj;
	char *name = (char *) obj->name;
	if (!ctx)
		return;
	if (obj->id) {
		ubus_remove_object(ctx, obj);
		hostapd_ubus_ref_dec();
	}

	free(name);
	obj->name = NULL;
}

static void hostapd_notify_ubus(struct ubus_object *obj, char *bssname, char *event)
{
	int ret = 0;
	char *event_type;

	if (!ctx || !obj)
		return;

	if (asprintf(&event_type, "bss.%s", event) < 0)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", bssname);
	ubus_notify(ctx, obj, event_type, b.head, -1);
	free(event_type);
}

static void hostapd_send_procd_event(char *bssname, char *event)
{
	char *name, *s;
	uint32_t id;
	void *v;

	if (!ctx || ubus_lookup_id(ctx, "service", &id))
		return;

	if (asprintf(&name, "hostapd.%s.%s", bssname, event) < 0)
		return;

	blob_buf_init(&b, 0);

	s = blobmsg_alloc_string_buffer(&b, "type", strlen(name) + 1);
	sprintf(s, "%s", name);
	blobmsg_add_string_buffer(&b);

	v = blobmsg_open_table(&b, "data");
	blobmsg_close_table(&b, v);

	ubus_invoke(ctx, id, "event", b.head, NULL, NULL, 1000);

	free(name);
}

static void hostapd_send_shared_event(struct ubus_object *obj, char *bssname, char *event)
{
	hostapd_send_procd_event(bssname, event);
	hostapd_notify_ubus(obj, bssname, event);
}

static void
hostapd_bss_del_ban(void *eloop_data, void *user_ctx)
{
	struct ubus_banned_client *ban = eloop_data;
	struct hostapd_data *hapd = user_ctx;

	avl_delete(&hapd->ubus.banned, &ban->avl);
	free(ban);
}

static void
hostapd_bss_ban_client(struct hostapd_data *hapd, u8 *addr, int time)
{
	struct ubus_banned_client *ban;

	if (time < 0)
		time = 0;

	ban = avl_find_element(&hapd->ubus.banned, addr, ban, avl);
	if (!ban) {
		if (!time)
			return;

		ban = os_zalloc(sizeof(*ban));
		memcpy(ban->addr, addr, sizeof(ban->addr));
		ban->avl.key = ban->addr;
		avl_insert(&hapd->ubus.banned, &ban->avl);
	} else {
		eloop_cancel_timeout(hostapd_bss_del_ban, ban, hapd);
		if (!time) {
			hostapd_bss_del_ban(ban, hapd);
			return;
		}
	}

	eloop_register_timeout(0, time * 1000, hostapd_bss_del_ban, ban, hapd);
}

static int
hostapd_bss_reload(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	int ret = hostapd_reload_config(hapd->iface, 1);

	hostapd_send_shared_event(&hapd->iface->interfaces->ubus, hapd->conf->iface, "reload");
	return ret;
}


static void
hostapd_parse_vht_map_blobmsg(uint16_t map)
{
	char label[4];
	int16_t val;
	int i;

	for (i = 0; i < 8; i++) {
		snprintf(label, 4, "%dss", i + 1);

		val = (map & (BIT(1) | BIT(0))) + 7;
		blobmsg_add_u16(&b, label, val == 10 ? -1 : val);
		map = map >> 2;
	}
}

static void
hostapd_parse_vht_capab_blobmsg(struct ieee80211_vht_capabilities *vhtc)
{
	void *supported_mcs;
	void *map;
	int i;

	static const struct {
		const char *name;
		uint32_t flag;
	} vht_capas[] = {
		{ "su_beamformee", VHT_CAP_SU_BEAMFORMEE_CAPABLE },
		{ "mu_beamformee", VHT_CAP_MU_BEAMFORMEE_CAPABLE },
	};

	for (i = 0; i < ARRAY_SIZE(vht_capas); i++)
		blobmsg_add_u8(&b, vht_capas[i].name,
				!!(vhtc->vht_capabilities_info & vht_capas[i].flag));

	supported_mcs = blobmsg_open_table(&b, "mcs_map");

	/* RX map */
	map = blobmsg_open_table(&b, "rx");
	hostapd_parse_vht_map_blobmsg(le_to_host16(vhtc->vht_supported_mcs_set.rx_map));
	blobmsg_close_table(&b, map);

	/* TX map */
	map = blobmsg_open_table(&b, "tx");
	hostapd_parse_vht_map_blobmsg(le_to_host16(vhtc->vht_supported_mcs_set.tx_map));
	blobmsg_close_table(&b, map);

	blobmsg_close_table(&b, supported_mcs);
}

static void
hostapd_parse_capab_blobmsg(struct sta_info *sta)
{
	void *r, *v;

	v = blobmsg_open_table(&b, "capabilities");

	if (sta->vht_capabilities) {
		r = blobmsg_open_table(&b, "vht");
		hostapd_parse_vht_capab_blobmsg(sta->vht_capabilities);
		blobmsg_close_table(&b, r);
	}

	/* ToDo: Add HT / HE capability parsing */

	blobmsg_close_table(&b, v);
}

static int
hostapd_bss_get_clients(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	struct hostap_sta_driver_data sta_driver_data;
	struct sta_info *sta;
	void *list, *c;
	char mac_buf[20];
	static const struct {
		const char *name;
		uint32_t flag;
	} sta_flags[] = {
		{ "auth", WLAN_STA_AUTH },
		{ "assoc", WLAN_STA_ASSOC },
		{ "authorized", WLAN_STA_AUTHORIZED },
		{ "preauth", WLAN_STA_PREAUTH },
		{ "wds", WLAN_STA_WDS },
		{ "wmm", WLAN_STA_WMM },
		{ "ht", WLAN_STA_HT },
		{ "vht", WLAN_STA_VHT },
		{ "he", WLAN_STA_HE },
		{ "wps", WLAN_STA_WPS },
		{ "mfp", WLAN_STA_MFP },
	};

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "freq", hapd->iface->freq);
	list = blobmsg_open_table(&b, "clients");
	for (sta = hapd->sta_list; sta; sta = sta->next) {
		void *r;
		int i;

		sprintf(mac_buf, MACSTR, MAC2STR(sta->addr));
		c = blobmsg_open_table(&b, mac_buf);
		for (i = 0; i < ARRAY_SIZE(sta_flags); i++)
			blobmsg_add_u8(&b, sta_flags[i].name,
				       !!(sta->flags & sta_flags[i].flag));

		r = blobmsg_open_array(&b, "rrm");
		for (i = 0; i < ARRAY_SIZE(sta->rrm_enabled_capa); i++)
			blobmsg_add_u32(&b, "", sta->rrm_enabled_capa[i]);
		blobmsg_close_array(&b, r);

		r = blobmsg_open_array(&b, "extended_capabilities");
		/* Check if client advertises extended capabilities */
		if (sta->ext_capability && sta->ext_capability[0] > 0) {
			for (i = 0; i < sta->ext_capability[0]; i++) {
				blobmsg_add_u32(&b, "", sta->ext_capability[1 + i]);
			}
		}
		blobmsg_close_array(&b, r);

		blobmsg_add_u32(&b, "aid", sta->aid);
#ifdef CONFIG_TAXONOMY
		r = blobmsg_alloc_string_buffer(&b, "signature", 1024);
		if (retrieve_sta_taxonomy(hapd, sta, r, 1024) > 0)
			blobmsg_add_string_buffer(&b);
#endif

		/* Driver information */
		if (hostapd_drv_read_sta_data(hapd, &sta_driver_data, sta->addr) >= 0) {
			r = blobmsg_open_table(&b, "bytes");
			blobmsg_add_u64(&b, "rx", sta_driver_data.rx_bytes);
			blobmsg_add_u64(&b, "tx", sta_driver_data.tx_bytes);
			blobmsg_close_table(&b, r);
			r = blobmsg_open_table(&b, "airtime");
			blobmsg_add_u64(&b, "rx", sta_driver_data.rx_airtime);
			blobmsg_add_u64(&b, "tx", sta_driver_data.tx_airtime);
			blobmsg_close_table(&b, r);
			r = blobmsg_open_table(&b, "packets");
			blobmsg_add_u32(&b, "rx", sta_driver_data.rx_packets);
			blobmsg_add_u32(&b, "tx", sta_driver_data.tx_packets);
			blobmsg_close_table(&b, r);
			r = blobmsg_open_table(&b, "rate");
			/* Rate in kbits */
			blobmsg_add_u32(&b, "rx", sta_driver_data.current_rx_rate * 100);
			blobmsg_add_u32(&b, "tx", sta_driver_data.current_tx_rate * 100);
			blobmsg_close_table(&b, r);
			blobmsg_add_u32(&b, "signal", sta_driver_data.signal);
		}

		hostapd_parse_capab_blobmsg(sta);

		blobmsg_close_table(&b, c);
	}
	blobmsg_close_array(&b, list);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
hostapd_bss_get_features(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);

	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "ht_supported", ht_supported(hapd->iface->hw_features));
	blobmsg_add_u8(&b, "vht_supported", vht_supported(hapd->iface->hw_features));
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

/* Imported from iw/util.c
 *  https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git/tree/util.c?id=4b25ae3537af48dbf9d0abf94132e5ba01b32c18#n200
 */
int ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11-2007 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	/* see 802.11ax D6.1 27.3.23.2 and Annex E */
	else if (freq == 5935)
		return 2;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq < 5950)
		return (freq - 5000) / 5;
	else if (freq <= 45000) /* DMG band lower limit */
		/* see 802.11ax D6.1 27.3.23.2 */
		return (freq - 5950) / 5;
	else if (freq >= 58320 && freq <= 70200)
		return (freq - 56160) / 2160;
	else
		return 0;
}

static int
hostapd_bss_get_status(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	void *airtime_table, *dfs_table, *rrm_table, *wnm_table;
	struct os_reltime now;
	char ssid[SSID_MAX_LEN + 1];
	char phy_name[17];
	size_t ssid_len = SSID_MAX_LEN;
	u8 channel = 0, op_class = 0;

	if (hapd->conf->ssid.ssid_len < SSID_MAX_LEN)
		ssid_len = hapd->conf->ssid.ssid_len;

	ieee80211_freq_to_channel_ext(hapd->iface->freq,
				      hapd->iconf->secondary_channel,
				      hostapd_get_oper_chwidth(hapd->iconf),
				      &op_class, &channel);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "status", hostapd_state_text(hapd->iface->state));
	blobmsg_printf(&b, "bssid", MACSTR, MAC2STR(hapd->conf->bssid));

	memset(ssid, 0, SSID_MAX_LEN + 1);
	memcpy(ssid, hapd->conf->ssid.ssid, ssid_len);
	blobmsg_add_string(&b, "ssid", ssid);

	blobmsg_add_u32(&b, "freq", hapd->iface->freq);
	blobmsg_add_u32(&b, "channel", channel);
	blobmsg_add_u32(&b, "op_class", op_class);
	blobmsg_add_u32(&b, "beacon_interval", hapd->iconf->beacon_int);

	snprintf(phy_name, 17, "%s", hapd->iface->phy);
	blobmsg_add_string(&b, "phy", phy_name);

	/* RRM */
	rrm_table = blobmsg_open_table(&b, "rrm");
	blobmsg_add_u64(&b, "neighbor_report_tx", hapd->openwrt_stats.rrm.neighbor_report_tx);
	blobmsg_close_table(&b, rrm_table);

	/* WNM */
	wnm_table = blobmsg_open_table(&b, "wnm");
	blobmsg_add_u64(&b, "bss_transition_query_rx", hapd->openwrt_stats.wnm.bss_transition_query_rx);
	blobmsg_add_u64(&b, "bss_transition_request_tx", hapd->openwrt_stats.wnm.bss_transition_request_tx);
	blobmsg_add_u64(&b, "bss_transition_response_rx", hapd->openwrt_stats.wnm.bss_transition_response_rx);
	blobmsg_close_table(&b, wnm_table);

	/* Airtime */
	airtime_table = blobmsg_open_table(&b, "airtime");
	blobmsg_add_u64(&b, "time", hapd->iface->last_channel_time);
	blobmsg_add_u64(&b, "time_busy", hapd->iface->last_channel_time_busy);
	blobmsg_add_u16(&b, "utilization", hapd->iface->channel_utilization);
	blobmsg_close_table(&b, airtime_table);

	/* DFS */
	dfs_table = blobmsg_open_table(&b, "dfs");
	blobmsg_add_u32(&b, "cac_seconds", hapd->iface->dfs_cac_ms / 1000);
	blobmsg_add_u8(&b, "cac_active", !!(hapd->iface->cac_started));
	os_reltime_age(&hapd->iface->dfs_cac_start, &now);
	blobmsg_add_u32(&b, "cac_seconds_left",
			hapd->iface->cac_started ? hapd->iface->dfs_cac_ms / 1000 - now.sec : 0);
	blobmsg_close_table(&b, dfs_table);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

enum {
	NOTIFY_RESPONSE,
	__NOTIFY_MAX
};

static const struct blobmsg_policy notify_policy[__NOTIFY_MAX] = {
	[NOTIFY_RESPONSE] = { "notify_response", BLOBMSG_TYPE_INT32 },
};

static int
hostapd_notify_response(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__NOTIFY_MAX];
	struct hostapd_data *hapd = get_hapd_from_object(obj);
	struct wpabuf *elems;
	const char *pos;
	size_t len;

	blobmsg_parse(notify_policy, __NOTIFY_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[NOTIFY_RESPONSE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	hapd->ubus.notify_response = blobmsg_get_u32(tb[NOTIFY_RESPONSE]);

	return UBUS_STATUS_OK;
}

enum {
	DEL_CLIENT_ADDR,
	DEL_CLIENT_REASON,
	DEL_CLIENT_DEAUTH,
	DEL_CLIENT_BAN_TIME,
	__DEL_CLIENT_MAX
};

static const struct blobmsg_policy del_policy[__DEL_CLIENT_MAX] = {
	[DEL_CLIENT_ADDR] = { "addr", BLOBMSG_TYPE_STRING },
	[DEL_CLIENT_REASON] = { "reason", BLOBMSG_TYPE_INT32 },
	[DEL_CLIENT_DEAUTH] = { "deauth", BLOBMSG_TYPE_INT8 },
	[DEL_CLIENT_BAN_TIME] = { "ban_time", BLOBMSG_TYPE_INT32 },
};

static int
hostapd_bss_del_client(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__DEL_CLIENT_MAX];
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	struct sta_info *sta;
	bool deauth = false;
	int reason;
	u8 addr[ETH_ALEN];

	blobmsg_parse(del_policy, __DEL_CLIENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[DEL_CLIENT_ADDR])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (hwaddr_aton(blobmsg_data(tb[DEL_CLIENT_ADDR]), addr))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[DEL_CLIENT_REASON])
		reason = blobmsg_get_u32(tb[DEL_CLIENT_REASON]);

	if (tb[DEL_CLIENT_DEAUTH])
		deauth = blobmsg_get_bool(tb[DEL_CLIENT_DEAUTH]);

	sta = ap_get_sta(hapd, addr);
	if (sta) {
		if (deauth) {
			hostapd_drv_sta_deauth(hapd, addr, reason);
			ap_sta_deauthenticate(hapd, sta, reason);
		} else {
			hostapd_drv_sta_disassoc(hapd, addr, reason);
			ap_sta_disassociate(hapd, sta, reason);
		}
	}

	if (tb[DEL_CLIENT_BAN_TIME])
		hostapd_bss_ban_client(hapd, addr, blobmsg_get_u32(tb[DEL_CLIENT_BAN_TIME]));

	return 0;
}

static void
blobmsg_add_macaddr(struct blob_buf *buf, const char *name, const u8 *addr)
{
	char *s;

	s = blobmsg_alloc_string_buffer(buf, name, 20);
	sprintf(s, MACSTR, MAC2STR(addr));
	blobmsg_add_string_buffer(buf);
}

static int
hostapd_bss_list_bans(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	struct ubus_banned_client *ban;
	void *c;

	blob_buf_init(&b, 0);
	c = blobmsg_open_array(&b, "clients");
	avl_for_each_element(&hapd->ubus.banned, ban, avl)
		blobmsg_add_macaddr(&b, NULL, ban->addr);
	blobmsg_close_array(&b, c);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

#ifdef CONFIG_WPS
static int
hostapd_bss_wps_start(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	int rc;
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);

	rc = hostapd_wps_button_pushed(hapd, NULL);

	if (rc != 0)
		return UBUS_STATUS_NOT_SUPPORTED;

	return 0;
}


static const char * pbc_status_enum_str(enum pbc_status status)
{
	switch (status) {
	case WPS_PBC_STATUS_DISABLE:
		return "Disabled";
	case WPS_PBC_STATUS_ACTIVE:
		return "Active";
	case WPS_PBC_STATUS_TIMEOUT:
		return "Timed-out";
	case WPS_PBC_STATUS_OVERLAP:
		return "Overlap";
	default:
		return "Unknown";
	}
}

static int
hostapd_bss_wps_status(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	int rc;
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "pbc_status", pbc_status_enum_str(hapd->wps_stats.pbc_status));
	blobmsg_add_string(&b, "last_wps_result",
			   (hapd->wps_stats.status == WPS_STATUS_SUCCESS ?
			    "Success":
			    (hapd->wps_stats.status == WPS_STATUS_FAILURE ?
			     "Failed" : "None")));

	/* If status == Failure - Add possible Reasons */
	if(hapd->wps_stats.status == WPS_STATUS_FAILURE &&
	   hapd->wps_stats.failure_reason > 0)
		blobmsg_add_string(&b, "reason", wps_ei_str(hapd->wps_stats.failure_reason));

	if (hapd->wps_stats.status)
		blobmsg_printf(&b, "peer_address", MACSTR, MAC2STR(hapd->wps_stats.peer_addr));

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
hostapd_bss_wps_cancel(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	int rc;
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);

	rc = hostapd_wps_cancel(hapd);

	if (rc != 0)
		return UBUS_STATUS_NOT_SUPPORTED;

	return 0;
}
#endif /* CONFIG_WPS */

static int
hostapd_bss_update_beacon(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	int rc;
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);

	rc = ieee802_11_set_beacon(hapd);

	if (rc != 0)
		return UBUS_STATUS_NOT_SUPPORTED;

	return 0;
}

enum {
	CONFIG_IFACE,
	CONFIG_FILE,
	__CONFIG_MAX
};

static const struct blobmsg_policy config_add_policy[__CONFIG_MAX] = {
	[CONFIG_IFACE] = { "iface", BLOBMSG_TYPE_STRING },
	[CONFIG_FILE] = { "config", BLOBMSG_TYPE_STRING },
};

static int
hostapd_config_add(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__CONFIG_MAX];
	struct hapd_interfaces *interfaces = get_hapd_interfaces_from_object(obj);
	char buf[128];

	blobmsg_parse(config_add_policy, __CONFIG_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[CONFIG_FILE] || !tb[CONFIG_IFACE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	snprintf(buf, sizeof(buf), "bss_config=%s:%s",
		blobmsg_get_string(tb[CONFIG_IFACE]),
		blobmsg_get_string(tb[CONFIG_FILE]));

	if (hostapd_add_iface(interfaces, buf))
		return UBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "pid", getpid());
	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

enum {
	CONFIG_REM_IFACE,
	__CONFIG_REM_MAX
};

static const struct blobmsg_policy config_remove_policy[__CONFIG_REM_MAX] = {
	[CONFIG_REM_IFACE] = { "iface", BLOBMSG_TYPE_STRING },
};

static int
hostapd_config_remove(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[__CONFIG_REM_MAX];
	struct hapd_interfaces *interfaces = get_hapd_interfaces_from_object(obj);
	char buf[128];

	blobmsg_parse(config_remove_policy, __CONFIG_REM_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[CONFIG_REM_IFACE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (hostapd_remove_iface(interfaces, blobmsg_get_string(tb[CONFIG_REM_IFACE])))
		return UBUS_STATUS_INVALID_ARGUMENT;

	return UBUS_STATUS_OK;
}


static void switch_chan_fallback_cb(void *eloop_data, void *user_ctx)
{
	struct hostapd_iface *iface = eloop_data;
	struct hostapd_freq_params *freq_params = user_ctx;

	hostapd_switch_channel_fallback(iface, freq_params);
}

#ifdef NEED_AP_MLME
static int
hostapd_bss_switch_chan(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct hostapd_data *hapd = get_hapd_from_object(obj);

	if (hapd)
		return hostapd_switch_chan(hapd->iface, msg);
	return UBUS_STATUS_INVALID_ARGUMENT;
}
static int
hostapd_bss_switch_chan_list(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct hostapd_data *hapd = get_hapd_from_object(obj);
	if (hapd)
		return hostapd_switch_chan_list(hapd->iface, msg);
	return UBUS_STATUS_INVALID_ARGUMENT;
}
#endif

enum {
	VENDOR_ELEMENTS,
	__VENDOR_ELEMENTS_MAX
};

static const struct blobmsg_policy ve_policy[__VENDOR_ELEMENTS_MAX] = {
	/* vendor elements are provided as hex-string */
	[VENDOR_ELEMENTS] = { "vendor_elements", BLOBMSG_TYPE_STRING },
};

static int
hostapd_vendor_elements(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__VENDOR_ELEMENTS_MAX];
	struct hostapd_data *hapd = get_hapd_from_object(obj);
	struct hostapd_bss_config *bss = hapd->conf;
	struct wpabuf *elems;
	const char *pos;
	size_t len;

	blobmsg_parse(ve_policy, __VENDOR_ELEMENTS_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[VENDOR_ELEMENTS])
		return UBUS_STATUS_INVALID_ARGUMENT;

	pos = blobmsg_data(tb[VENDOR_ELEMENTS]);
	len = os_strlen(pos);
	if (len & 0x01)
			return UBUS_STATUS_INVALID_ARGUMENT;

	len /= 2;
	if (len == 0) {
		wpabuf_free(bss->vendor_elements);
		bss->vendor_elements = NULL;
		return 0;
	}

	elems = wpabuf_alloc(len);
	if (elems == NULL)
		return 1;

	if (hexstr2bin(pos, wpabuf_put(elems, len), len)) {
		wpabuf_free(elems);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	wpabuf_free(bss->vendor_elements);
	bss->vendor_elements = elems;

	/* update beacons if vendor elements were set successfully */
	if (ieee802_11_update_beacons(hapd->iface) != 0)
		return UBUS_STATUS_NOT_SUPPORTED;
	return UBUS_STATUS_OK;
}

static void
hostapd_rrm_print_nr(struct hostapd_neighbor_entry *nr)
{
	const u8 *data;
	char *str;
	int len;

	blobmsg_printf(&b, "", MACSTR, MAC2STR(nr->bssid));

	str = blobmsg_alloc_string_buffer(&b, "", nr->ssid.ssid_len + 1);
	memcpy(str, nr->ssid.ssid, nr->ssid.ssid_len);
	str[nr->ssid.ssid_len] = 0;
	blobmsg_add_string_buffer(&b);

	len = wpabuf_len(nr->nr);
	str = blobmsg_alloc_string_buffer(&b, "", 2 * len + 1);
	wpa_snprintf_hex(str, 2 * len + 1, wpabuf_head_u8(nr->nr), len);
	blobmsg_add_string_buffer(&b);
}

enum {
	BSS_MGMT_EN_NEIGHBOR,
	BSS_MGMT_EN_BEACON,
	BSS_MGMT_EN_LINK_MEASUREMENT,
#ifdef CONFIG_WNM_AP
	BSS_MGMT_EN_BSS_TRANSITION,
#endif
	__BSS_MGMT_EN_MAX
};

static bool
__hostapd_bss_mgmt_enable_f(struct hostapd_data *hapd, int flag)
{
	struct hostapd_bss_config *bss = hapd->conf;
	uint32_t flags;

	switch (flag) {
	case BSS_MGMT_EN_NEIGHBOR:
		if (bss->radio_measurements[0] &
		    WLAN_RRM_CAPS_NEIGHBOR_REPORT)
			return false;

		bss->radio_measurements[0] |=
			WLAN_RRM_CAPS_NEIGHBOR_REPORT;
		hostapd_neighbor_set_own_report(hapd);
		return true;
	case BSS_MGMT_EN_BEACON:
		flags = WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE |
			WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE |
			WLAN_RRM_CAPS_BEACON_REPORT_TABLE;

		if (bss->radio_measurements[0] & flags == flags)
			return false;

		bss->radio_measurements[0] |= (u8) flags;
		return true;
	case BSS_MGMT_EN_LINK_MEASUREMENT:
		flags = WLAN_RRM_CAPS_LINK_MEASUREMENT;

		if (bss->radio_measurements[0] & flags == flags)
			return false;

		bss->radio_measurements[0] |= (u8) flags;
		return true;
#ifdef CONFIG_WNM_AP
	case BSS_MGMT_EN_BSS_TRANSITION:
		if (bss->bss_transition)
			return false;

		bss->bss_transition = 1;
		return true;
#endif
	}
}

static void
__hostapd_bss_mgmt_enable(struct hostapd_data *hapd, uint32_t flags)
{
	bool update = false;
	int i;

	for (i = 0; i < __BSS_MGMT_EN_MAX; i++) {
		if (!(flags & (1 << i)))
			continue;

		update |= __hostapd_bss_mgmt_enable_f(hapd, i);
	}

	if (update)
		ieee802_11_update_beacons(hapd->iface);
}


static const struct blobmsg_policy bss_mgmt_enable_policy[__BSS_MGMT_EN_MAX] = {
	[BSS_MGMT_EN_NEIGHBOR] = { "neighbor_report", BLOBMSG_TYPE_BOOL },
	[BSS_MGMT_EN_BEACON] = { "beacon_report", BLOBMSG_TYPE_BOOL },
	[BSS_MGMT_EN_LINK_MEASUREMENT] = { "link_measurement", BLOBMSG_TYPE_BOOL },
#ifdef CONFIG_WNM_AP
	[BSS_MGMT_EN_BSS_TRANSITION] = { "bss_transition", BLOBMSG_TYPE_BOOL },
#endif
};

static int
hostapd_bss_mgmt_enable(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)

{
	struct hostapd_data *hapd = get_hapd_from_object(obj);
	struct blob_attr *tb[__BSS_MGMT_EN_MAX];
	struct blob_attr *cur;
	uint32_t flags = 0;
	int i;
	bool neigh = false, beacon = false;

	blobmsg_parse(bss_mgmt_enable_policy, __BSS_MGMT_EN_MAX, tb, blob_data(msg), blob_len(msg));

	for (i = 0; i < ARRAY_SIZE(tb); i++) {
		if (!tb[i] || !blobmsg_get_bool(tb[i]))
			continue;

		flags |= (1 << i);
	}

	__hostapd_bss_mgmt_enable(hapd, flags);

	return 0;
}


static void
hostapd_rrm_nr_enable(struct hostapd_data *hapd)
{
	__hostapd_bss_mgmt_enable(hapd, 1 << BSS_MGMT_EN_NEIGHBOR);
}

static int
hostapd_rrm_nr_get_own(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct hostapd_data *hapd = get_hapd_from_object(obj);
	struct hostapd_neighbor_entry *nr;
	void *c;

	hostapd_rrm_nr_enable(hapd);

	nr = hostapd_neighbor_get(hapd, hapd->own_addr, NULL);
	if (!nr)
		return UBUS_STATUS_NOT_FOUND;

	blob_buf_init(&b, 0);

	c = blobmsg_open_array(&b, "value");
	hostapd_rrm_print_nr(nr);
	blobmsg_close_array(&b, c);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
hostapd_rrm_nr_list(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct hostapd_data *hapd = get_hapd_from_object(obj);
	struct hostapd_neighbor_entry *nr;
	void *c;

	hostapd_rrm_nr_enable(hapd);
	blob_buf_init(&b, 0);

	c = blobmsg_open_array(&b, "list");
	dl_list_for_each(nr, &hapd->nr_db, struct hostapd_neighbor_entry, list) {
		void *cur;

		if (!memcmp(nr->bssid, hapd->own_addr, ETH_ALEN))
			continue;

		cur = blobmsg_open_array(&b, NULL);
		hostapd_rrm_print_nr(nr);
		blobmsg_close_array(&b, cur);
	}
	blobmsg_close_array(&b, c);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

enum {
	NR_SET_LIST,
	__NR_SET_LIST_MAX
};

static const struct blobmsg_policy nr_set_policy[__NR_SET_LIST_MAX] = {
	[NR_SET_LIST] = { "list", BLOBMSG_TYPE_ARRAY },
};


static void
hostapd_rrm_nr_clear(struct hostapd_data *hapd)
{
	struct hostapd_neighbor_entry *nr;

restart:
	dl_list_for_each(nr, &hapd->nr_db, struct hostapd_neighbor_entry, list) {
		if (!memcmp(nr->bssid, hapd->own_addr, ETH_ALEN))
			continue;

		hostapd_neighbor_remove(hapd, nr->bssid, &nr->ssid);
		goto restart;
	}
}

static int
hostapd_rrm_nr_set(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	static const struct blobmsg_policy nr_e_policy[] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
	};
	struct hostapd_data *hapd = get_hapd_from_object(obj);
	struct blob_attr *tb_l[__NR_SET_LIST_MAX];
	struct blob_attr *tb[ARRAY_SIZE(nr_e_policy)];
	struct blob_attr *cur;
	int ret = 0;
	int rem;

	hostapd_rrm_nr_enable(hapd);

	blobmsg_parse(nr_set_policy, __NR_SET_LIST_MAX, tb_l, blob_data(msg), blob_len(msg));
	if (!tb_l[NR_SET_LIST])
		return UBUS_STATUS_INVALID_ARGUMENT;

	hostapd_rrm_nr_clear(hapd);
	blobmsg_for_each_attr(cur, tb_l[NR_SET_LIST], rem) {
		struct wpa_ssid_value ssid;
		struct wpabuf *data;
		u8 bssid[ETH_ALEN];
		char *s, *nr_s;

		blobmsg_parse_array(nr_e_policy, ARRAY_SIZE(nr_e_policy), tb, blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tb[0] || !tb[1] || !tb[2])
			goto invalid;

		/* Neighbor Report binary */
		nr_s = blobmsg_get_string(tb[2]);
		data = wpabuf_parse_bin(nr_s);
		if (!data)
			goto invalid;

		/* BSSID */
		s = blobmsg_get_string(tb[0]);
		if (strlen(s) == 0) {
			/* Copy BSSID from neighbor report */
			if (hwaddr_compact_aton(nr_s, bssid))
				goto invalid;
		} else if (hwaddr_aton(s, bssid)) {
			goto invalid;
		}

		/* SSID */
		s = blobmsg_get_string(tb[1]);
		if (strlen(s) == 0) {
			/* Copy SSID from hostapd BSS conf */
			memcpy(&ssid, &hapd->conf->ssid, sizeof(ssid));
		} else {
			ssid.ssid_len = strlen(s);
			if (ssid.ssid_len > sizeof(ssid.ssid))
				goto invalid;

			memcpy(&ssid, s, ssid.ssid_len);
		}

		hostapd_neighbor_set(hapd, bssid, &ssid, data, NULL, NULL, 0, 0);
		wpabuf_free(data);
		continue;

invalid:
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return 0;
}

enum {
	BEACON_REQ_ADDR,
	BEACON_REQ_MODE,
	BEACON_REQ_OP_CLASS,
	BEACON_REQ_CHANNEL,
	BEACON_REQ_DURATION,
	BEACON_REQ_BSSID,
	BEACON_REQ_SSID,
	__BEACON_REQ_MAX,
};

static const struct blobmsg_policy beacon_req_policy[__BEACON_REQ_MAX] = {
	[BEACON_REQ_ADDR] = { "addr", BLOBMSG_TYPE_STRING },
	[BEACON_REQ_OP_CLASS] { "op_class", BLOBMSG_TYPE_INT32 },
	[BEACON_REQ_CHANNEL] { "channel", BLOBMSG_TYPE_INT32 },
	[BEACON_REQ_DURATION] { "duration", BLOBMSG_TYPE_INT32 },
	[BEACON_REQ_MODE] { "mode", BLOBMSG_TYPE_INT32 },
	[BEACON_REQ_BSSID] { "bssid", BLOBMSG_TYPE_STRING },
	[BEACON_REQ_SSID] { "ssid", BLOBMSG_TYPE_STRING },
};

static int
hostapd_rrm_beacon_req(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *ureq, const char *method,
		       struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	struct blob_attr *tb[__BEACON_REQ_MAX];
	struct blob_attr *cur;
	struct wpabuf *req;
	u8 bssid[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	u8 addr[ETH_ALEN];
	int mode, rem, ret;
	int buf_len = 13;

	blobmsg_parse(beacon_req_policy, __BEACON_REQ_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[BEACON_REQ_ADDR] || !tb[BEACON_REQ_MODE] || !tb[BEACON_REQ_DURATION] ||
	    !tb[BEACON_REQ_OP_CLASS] || !tb[BEACON_REQ_CHANNEL])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[BEACON_REQ_SSID])
		buf_len += blobmsg_data_len(tb[BEACON_REQ_SSID]) + 2 - 1;

	mode = blobmsg_get_u32(tb[BEACON_REQ_MODE]);
	if (hwaddr_aton(blobmsg_data(tb[BEACON_REQ_ADDR]), addr))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[BEACON_REQ_BSSID] &&
	    hwaddr_aton(blobmsg_data(tb[BEACON_REQ_BSSID]), bssid))
		return UBUS_STATUS_INVALID_ARGUMENT;

	req = wpabuf_alloc(buf_len);
	if (!req)
		return UBUS_STATUS_UNKNOWN_ERROR;

	/* 1: regulatory class */
	wpabuf_put_u8(req, blobmsg_get_u32(tb[BEACON_REQ_OP_CLASS]));

	/* 2: channel number */
	wpabuf_put_u8(req, blobmsg_get_u32(tb[BEACON_REQ_CHANNEL]));

	/* 3-4: randomization interval */
	wpabuf_put_le16(req, 0);

	/* 5-6: duration */
	wpabuf_put_le16(req, blobmsg_get_u32(tb[BEACON_REQ_DURATION]));

	/* 7: mode */
	wpabuf_put_u8(req, blobmsg_get_u32(tb[BEACON_REQ_MODE]));

	/* 8-13: BSSID */
	wpabuf_put_data(req, bssid, ETH_ALEN);

	if ((cur = tb[BEACON_REQ_SSID]) != NULL) {
		wpabuf_put_u8(req, WLAN_EID_SSID);
		wpabuf_put_u8(req, blobmsg_data_len(cur) - 1);
		wpabuf_put_data(req, blobmsg_data(cur), blobmsg_data_len(cur) - 1);
	}

	ret = hostapd_send_beacon_req(hapd, addr, 0, req);
	if (ret < 0)
		return -ret;

	return 0;
}

enum {
	LM_REQ_ADDR,
	LM_REQ_TX_POWER_USED,
	LM_REQ_TX_POWER_MAX,
	__LM_REQ_MAX,
};

static const struct blobmsg_policy lm_req_policy[__LM_REQ_MAX] = {
	[LM_REQ_ADDR] = { "addr", BLOBMSG_TYPE_STRING },
	[LM_REQ_TX_POWER_USED] = { "tx-power-used", BLOBMSG_TYPE_INT32 },
	[LM_REQ_TX_POWER_MAX] = { "tx-power-max", BLOBMSG_TYPE_INT32 },
};

static int
hostapd_rrm_lm_req(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *ureq, const char *method,
		   struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	struct blob_attr *tb[__LM_REQ_MAX];
	struct wpabuf *buf;
	u8 addr[ETH_ALEN];
	int ret;
	int8_t txp_used, txp_max;

	txp_used = 0;
	txp_max = 0;

	blobmsg_parse(lm_req_policy, __LM_REQ_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[LM_REQ_ADDR])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[LM_REQ_TX_POWER_USED])
		txp_used = (int8_t) blobmsg_get_u32(tb[LM_REQ_TX_POWER_USED]);

	if (tb[LM_REQ_TX_POWER_MAX])
		txp_max = (int8_t) blobmsg_get_u32(tb[LM_REQ_TX_POWER_MAX]);

	if (hwaddr_aton(blobmsg_data(tb[LM_REQ_ADDR]), addr))
		return UBUS_STATUS_INVALID_ARGUMENT;

	buf = wpabuf_alloc(5);
	if (!buf)
		return UBUS_STATUS_UNKNOWN_ERROR;

	wpabuf_put_u8(buf, WLAN_ACTION_RADIO_MEASUREMENT);
	wpabuf_put_u8(buf, WLAN_RRM_LINK_MEASUREMENT_REQUEST);
	wpabuf_put_u8(buf, 1);
	/* TX-Power used */
	wpabuf_put_u8(buf, txp_used);
	/* Max TX Power */
	wpabuf_put_u8(buf, txp_max);

	ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, addr,
				      wpabuf_head(buf), wpabuf_len(buf));

	wpabuf_free(buf);
	if (ret < 0)
		return -ret;

	return 0;
}


void hostapd_ubus_handle_link_measurement(struct hostapd_data *hapd, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) data;
	const u8 *pos, *end;
	u8 token;

	end = data + len;
	token = mgmt->u.action.u.rrm.dialog_token;
	pos = mgmt->u.action.u.rrm.variable;

	if (end - pos < 8)
		return;

	if (!hapd->ubus.obj.has_subscribers)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_macaddr(&b, "address", mgmt->sa);
	blobmsg_add_u16(&b, "dialog-token", token);
	blobmsg_add_u16(&b, "rx-antenna-id", pos[4]);
	blobmsg_add_u16(&b, "tx-antenna-id", pos[5]);
	blobmsg_add_u16(&b, "rcpi", pos[6]);
	blobmsg_add_u16(&b, "rsni", pos[7]);

	ubus_notify(ctx, &hapd->ubus.obj, "link-measurement-report", b.head, -1);
}


#ifdef CONFIG_WNM_AP

static int
hostapd_bss_tr_send(struct hostapd_data *hapd, u8 *addr, bool disassoc_imminent, bool abridged,
		    u16 disassoc_timer, u8 validity_period, u8 dialog_token,
		    struct blob_attr *neighbors)
{
	struct blob_attr *cur;
	struct sta_info *sta;
	int nr_len = 0;
	int rem;
	u8 *nr = NULL;
	u8 req_mode = 0;

	sta = ap_get_sta(hapd, addr);
	if (!sta)
		return UBUS_STATUS_NOT_FOUND;

	if (neighbors) {
		u8 *nr_cur;

		if (blobmsg_check_array(neighbors,
					BLOBMSG_TYPE_STRING) < 0)
			return UBUS_STATUS_INVALID_ARGUMENT;

		blobmsg_for_each_attr(cur, neighbors, rem) {
			int len = strlen(blobmsg_get_string(cur));

			if (len % 2)
				return UBUS_STATUS_INVALID_ARGUMENT;

			nr_len += (len / 2) + 2;
		}

		if (nr_len) {
			nr = os_zalloc(nr_len);
			if (!nr)
				return UBUS_STATUS_UNKNOWN_ERROR;
		}

		nr_cur = nr;
		blobmsg_for_each_attr(cur, neighbors, rem) {
			int len = strlen(blobmsg_get_string(cur)) / 2;

			*nr_cur++ = WLAN_EID_NEIGHBOR_REPORT;
			*nr_cur++ = (u8) len;
			if (hexstr2bin(blobmsg_data(cur), nr_cur, len)) {
				free(nr);
				return UBUS_STATUS_INVALID_ARGUMENT;
			}

			nr_cur += len;
		}
	}

	if (nr)
		req_mode |= WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED;

	if (abridged)
		req_mode |= WNM_BSS_TM_REQ_ABRIDGED;

	if (disassoc_imminent)
		req_mode |= WNM_BSS_TM_REQ_DISASSOC_IMMINENT;

	if (wnm_send_bss_tm_req(hapd, sta, req_mode, disassoc_timer, validity_period, NULL,
				dialog_token, NULL, nr, nr_len, NULL, 0))
		return UBUS_STATUS_UNKNOWN_ERROR;

	return 0;
}

enum {
	BSS_TR_ADDR,
	BSS_TR_DA_IMMINENT,
	BSS_TR_DA_TIMER,
	BSS_TR_VALID_PERIOD,
	BSS_TR_NEIGHBORS,
	BSS_TR_ABRIDGED,
	BSS_TR_DIALOG_TOKEN,
	__BSS_TR_DISASSOC_MAX
};

static const struct blobmsg_policy bss_tr_policy[__BSS_TR_DISASSOC_MAX] = {
	[BSS_TR_ADDR] = { "addr", BLOBMSG_TYPE_STRING },
	[BSS_TR_DA_IMMINENT] = { "disassociation_imminent", BLOBMSG_TYPE_BOOL },
	[BSS_TR_DA_TIMER] = { "disassociation_timer", BLOBMSG_TYPE_INT32 },
	[BSS_TR_VALID_PERIOD] = { "validity_period", BLOBMSG_TYPE_INT32 },
	[BSS_TR_NEIGHBORS] = { "neighbors", BLOBMSG_TYPE_ARRAY },
	[BSS_TR_ABRIDGED] = { "abridged", BLOBMSG_TYPE_BOOL },
	[BSS_TR_DIALOG_TOKEN] = { "dialog_token", BLOBMSG_TYPE_INT32 },
};

static int
hostapd_bss_transition_request(struct ubus_context *ctx, struct ubus_object *obj,
			       struct ubus_request_data *ureq, const char *method,
			       struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	struct blob_attr *tb[__BSS_TR_DISASSOC_MAX];
	struct sta_info *sta;
	u32 da_timer = 0;
	u32 valid_period = 0;
	u8 addr[ETH_ALEN];
	u32 dialog_token = 1;
	bool abridged;
	bool da_imminent;

	blobmsg_parse(bss_tr_policy, __BSS_TR_DISASSOC_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[BSS_TR_ADDR])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (hwaddr_aton(blobmsg_data(tb[BSS_TR_ADDR]), addr))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[BSS_TR_DA_TIMER])
		da_timer = blobmsg_get_u32(tb[BSS_TR_DA_TIMER]);

	if (tb[BSS_TR_VALID_PERIOD])
		valid_period = blobmsg_get_u32(tb[BSS_TR_VALID_PERIOD]);

	if (tb[BSS_TR_DIALOG_TOKEN])
		dialog_token = blobmsg_get_u32(tb[BSS_TR_DIALOG_TOKEN]);

	da_imminent = !!(tb[BSS_TR_DA_IMMINENT] && blobmsg_get_bool(tb[BSS_TR_DA_IMMINENT]));
	abridged = !!(tb[BSS_TR_ABRIDGED] && blobmsg_get_bool(tb[BSS_TR_ABRIDGED]));

	return hostapd_bss_tr_send(hapd, addr, da_imminent, abridged, da_timer, valid_period,
				   dialog_token, tb[BSS_TR_NEIGHBORS]);
}

enum {
	WNM_DISASSOC_ADDR,
	WNM_DISASSOC_DURATION,
	WNM_DISASSOC_NEIGHBORS,
	WNM_DISASSOC_ABRIDGED,
	__WNM_DISASSOC_MAX,
};

static const struct blobmsg_policy wnm_disassoc_policy[__WNM_DISASSOC_MAX] = {
	[WNM_DISASSOC_ADDR] = { "addr", BLOBMSG_TYPE_STRING },
	[WNM_DISASSOC_DURATION] { "duration", BLOBMSG_TYPE_INT32 },
	[WNM_DISASSOC_NEIGHBORS] { "neighbors", BLOBMSG_TYPE_ARRAY },
	[WNM_DISASSOC_ABRIDGED] { "abridged", BLOBMSG_TYPE_BOOL },
};

static int
hostapd_wnm_disassoc_imminent(struct ubus_context *ctx, struct ubus_object *obj,
			      struct ubus_request_data *ureq, const char *method,
			      struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	struct blob_attr *tb[__WNM_DISASSOC_MAX];
	struct sta_info *sta;
	int duration = 10;
	u8 addr[ETH_ALEN];
	bool abridged;

	blobmsg_parse(wnm_disassoc_policy, __WNM_DISASSOC_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[WNM_DISASSOC_ADDR])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (hwaddr_aton(blobmsg_data(tb[WNM_DISASSOC_ADDR]), addr))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[WNM_DISASSOC_DURATION])
		duration = blobmsg_get_u32(tb[WNM_DISASSOC_DURATION]);

	abridged = !!(tb[WNM_DISASSOC_ABRIDGED] && blobmsg_get_bool(tb[WNM_DISASSOC_ABRIDGED]));

	return hostapd_bss_tr_send(hapd, addr, true, abridged, duration, duration,
				   1, tb[WNM_DISASSOC_NEIGHBORS]);
}
#endif

#ifdef CONFIG_AIRTIME_POLICY
enum {
	UPDATE_AIRTIME_STA,
	UPDATE_AIRTIME_WEIGHT,
	__UPDATE_AIRTIME_MAX,
};


static const struct blobmsg_policy airtime_policy[__UPDATE_AIRTIME_MAX] = {
	[UPDATE_AIRTIME_STA] = { "sta", BLOBMSG_TYPE_STRING },
	[UPDATE_AIRTIME_WEIGHT] = { "weight", BLOBMSG_TYPE_INT32 },
};

static int
hostapd_bss_update_airtime(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *ureq, const char *method,
			   struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	struct blob_attr *tb[__UPDATE_AIRTIME_MAX];
	struct sta_info *sta = NULL;
	u8 addr[ETH_ALEN];
	int weight;

	blobmsg_parse(airtime_policy, __UPDATE_AIRTIME_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UPDATE_AIRTIME_WEIGHT])
		return UBUS_STATUS_INVALID_ARGUMENT;

	weight = blobmsg_get_u32(tb[UPDATE_AIRTIME_WEIGHT]);

	if (!tb[UPDATE_AIRTIME_STA]) {
		if (!weight)
			return UBUS_STATUS_INVALID_ARGUMENT;

		hapd->conf->airtime_weight = weight;
		return 0;
	}

	if (hwaddr_aton(blobmsg_data(tb[UPDATE_AIRTIME_STA]), addr))
		return UBUS_STATUS_INVALID_ARGUMENT;

	sta = ap_get_sta(hapd, addr);
	if (!sta)
		return UBUS_STATUS_NOT_FOUND;

	sta->dyn_airtime_weight = weight;
	airtime_policy_new_sta(hapd, sta);

	return 0;
}
#endif

static int
hostapd_bss_get_client_account(struct ubus_context *ctx, struct ubus_object *obj,
			      struct ubus_request_data *req, const char *method,
			      struct blob_attr *msg)
{
	struct hostapd_data *hapd = container_of(obj, struct hostapd_data, ubus.obj);
	struct sta_info *sta = NULL;
	u8 addr[ETH_ALEN];
	struct blob_attr *tb[__STA_ACCOUNT_MAX];

	blobmsg_parse(sta_account_policy, __STA_ACCOUNT_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[STA_ACCOUNT_ADDR])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (hwaddr_aton(blobmsg_data(tb[STA_ACCOUNT_ADDR]), addr))
		return UBUS_STATUS_INVALID_ARGUMENT;
	sta = ap_get_sta(hapd, addr);
	if (sta == NULL) {
		return UBUS_STATUS_NOT_FOUND;
	}
	blob_buf_init(&b, 0);
	blobmsg_add_station_accounting(&b, "station", sta, NULL,  NULL, 0);
	blobmsg_add_hapd_id(&b, hapd);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}


static const struct ubus_method bss_methods[] = {
	UBUS_METHOD_NOARG("reload", hostapd_bss_reload),
	UBUS_METHOD_NOARG("get_clients", hostapd_bss_get_clients),
	UBUS_METHOD_NOARG("get_status", hostapd_bss_get_status),
	UBUS_METHOD("del_client", hostapd_bss_del_client, del_policy),
#ifdef CONFIG_AIRTIME_POLICY
	UBUS_METHOD("update_airtime", hostapd_bss_update_airtime, airtime_policy),
#endif
	UBUS_METHOD_NOARG("list_bans", hostapd_bss_list_bans),
#ifdef CONFIG_WPS
	UBUS_METHOD_NOARG("wps_start", hostapd_bss_wps_start),
	UBUS_METHOD_NOARG("wps_status", hostapd_bss_wps_status),
	UBUS_METHOD_NOARG("wps_cancel", hostapd_bss_wps_cancel),
#endif
	UBUS_METHOD_NOARG("update_beacon", hostapd_bss_update_beacon),
	UBUS_METHOD_NOARG("get_features", hostapd_bss_get_features),
#ifdef NEED_AP_MLME
	UBUS_METHOD("switch_chan", hostapd_bss_switch_chan, csa_policy),
	UBUS_METHOD("switch_chan_list", hostapd_bss_switch_chan_list, csa_list_policy),
#endif
	UBUS_METHOD("set_vendor_elements", hostapd_vendor_elements, ve_policy),
	UBUS_METHOD("notify_response", hostapd_notify_response, notify_policy),
	UBUS_METHOD("bss_mgmt_enable", hostapd_bss_mgmt_enable, bss_mgmt_enable_policy),
	UBUS_METHOD_NOARG("rrm_nr_get_own", hostapd_rrm_nr_get_own),
	UBUS_METHOD_NOARG("rrm_nr_list", hostapd_rrm_nr_list),
	UBUS_METHOD("rrm_nr_set", hostapd_rrm_nr_set, nr_set_policy),
	UBUS_METHOD("rrm_beacon_req", hostapd_rrm_beacon_req, beacon_req_policy),
	UBUS_METHOD("link_measurement_req", hostapd_rrm_lm_req, lm_req_policy),
#ifdef CONFIG_WNM_AP
	UBUS_METHOD("wnm_disassoc_imminent", hostapd_wnm_disassoc_imminent, wnm_disassoc_policy),
	UBUS_METHOD("bss_transition_request", hostapd_bss_transition_request, bss_tr_policy),
#endif
	UBUS_METHOD("get_client_account", hostapd_bss_get_client_account, sta_account_policy),
};

static struct ubus_object_type bss_object_type =
	UBUS_OBJECT_TYPE("hostapd_bss", bss_methods);

static int avl_compare_macaddr(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, ETH_ALEN);
}

static void hostapd_ubus_accounting_interim_update(void *eloop_ctx,	void *);
static bool hostapd_ubus_accounting_init(struct hostapd_data *hapd)
{
	int interval = hapd->conf->acct_interim_interval;
	if (!interval)
		interval = ACCT_DEFAULT_UPDATE_INTERVAL;
	eloop_register_timeout(interval, 0, hostapd_ubus_accounting_interim_update,
			hapd, NULL);
	return true;
}
static void hostapd_ubus_accounting_stop(struct hostapd_data *hapd)
{
	eloop_cancel_timeout(hostapd_ubus_accounting_interim_update, hapd, NULL);
}

void hostapd_ubus_add_bss(struct hostapd_data *hapd)
{
	struct ubus_object *obj = &hapd->ubus.obj;
	char *name;
	int ret;

#ifdef CONFIG_MESH
	if (hapd->conf->mesh & MESH_ENABLED)
		return;
#endif

	if (!hostapd_ubus_init())
		return;

	if (obj->id) {
		return;
	}

	if (asprintf(&name, "hostapd.%s", hapd->conf->iface) < 0)
		return;

	if (!hostapd_ubus_accounting_init(hapd))
		return;

	avl_init(&hapd->ubus.banned, avl_compare_macaddr, false, NULL);
	obj->name = name;
	obj->type = &bss_object_type;
	obj->methods = bss_object_type.methods;
	obj->n_methods = bss_object_type.n_methods;
	ret = ubus_add_object(ctx, obj);
	hostapd_ubus_ref_inc();

	hostapd_send_shared_event(&hapd->iface->interfaces->ubus, hapd->conf->iface, "add");
}

void hostapd_ubus_free_bss(struct hostapd_data *hapd)
{
	struct ubus_object *obj = &hapd->ubus.obj;
	char *name = (char *) obj->name;

#ifdef CONFIG_MESH
	if (hapd->conf->mesh & MESH_ENABLED)
		return;
#endif

	if (!ctx)
		return;

	hostapd_send_shared_event(&hapd->iface->interfaces->ubus, hapd->conf->iface, "remove");
	hostapd_ubus_accounting_stop(hapd);

	if (obj->id) {
		ubus_remove_object(ctx, obj);
		hostapd_ubus_ref_dec();
	}

	free(name);
	obj->name = NULL;
}

static void
hostapd_ubus_vlan_action(struct hostapd_data *hapd, struct hostapd_vlan *vlan,
			 const char *action)
{
	struct vlan_description *desc = &vlan->vlan_desc;
	void *c;
	int i;

	if (!hapd->ubus.obj.has_subscribers)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "ifname", vlan->ifname);
	blobmsg_add_string(&b, "bridge", vlan->bridge);
	blobmsg_add_u32(&b, "vlan_id", vlan->vlan_id);

	if (desc->notempty) {
		blobmsg_add_u32(&b, "untagged", desc->untagged);
		c = blobmsg_open_array(&b, "tagged");
		for (i = 0; i < ARRAY_SIZE(desc->tagged) && desc->tagged[i]; i++)
			blobmsg_add_u32(&b, "", desc->tagged[i]);
		blobmsg_close_array(&b, c);
	}

	ubus_notify(ctx, &hapd->ubus.obj, action, b.head, -1);
}

void hostapd_ubus_add_vlan(struct hostapd_data *hapd, struct hostapd_vlan *vlan)
{
	hostapd_ubus_vlan_action(hapd, vlan, "vlan_add");
}

void hostapd_ubus_remove_vlan(struct hostapd_data *hapd, struct hostapd_vlan *vlan)
{
	hostapd_ubus_vlan_action(hapd, vlan, "vlan_remove");
}

static const struct ubus_method daemon_methods[] = {
	UBUS_METHOD("config_add", hostapd_config_add, config_add_policy),
	UBUS_METHOD("config_remove", hostapd_config_remove, config_remove_policy),
};

static struct ubus_object_type daemon_object_type =
	UBUS_OBJECT_TYPE("hostapd", daemon_methods);

void hostapd_ubus_add(struct hapd_interfaces *interfaces)
{
	struct ubus_object *obj = &interfaces->ubus;
	int ret;

	if (!hostapd_ubus_init())
		return;

	obj->name = strdup("hostapd");

	obj->type = &daemon_object_type;
	obj->methods = daemon_object_type.methods;
	obj->n_methods = daemon_object_type.n_methods;
	ret = ubus_add_object(ctx, obj);
	hostapd_ubus_ref_inc();
}

void hostapd_ubus_free(struct hapd_interfaces *interfaces)
{
	struct ubus_object *obj = &interfaces->ubus;
	char *name = (char *) obj->name;

	if (!ctx)
		return;

	if (obj->id) {
		ubus_remove_object(ctx, obj);
		hostapd_ubus_ref_dec();
	}

	free(name);
}

struct ubus_event_req {
	struct ubus_notify_request nreq;
	int resp;
};

static void
ubus_event_cb(struct ubus_notify_request *req, int idx, int ret)
{
	struct ubus_event_req *ureq = container_of(req, struct ubus_event_req, nreq);

	ureq->resp = ret;
}

static void blobmsg_add_hapd_id(struct blob_buf *buf, struct hostapd_data *hapd)
{
	if (hapd->conf->uci_device)
		blobmsg_add_string(buf, "device", hapd->conf->uci_device);
	blobmsg_add_macaddr(buf, "bssid", hapd->own_addr);
	blobmsg_add_string(buf, "iface", hapd->conf->iface);
}
int hostapd_ubus_handle_event(struct hostapd_data *hapd, struct hostapd_ubus_request *req)
{
	struct ubus_banned_client *ban;
	const char *types[HOSTAPD_UBUS_TYPE_MAX] = {
		[HOSTAPD_UBUS_PROBE_REQ] = "probe",
		[HOSTAPD_UBUS_AUTH_REQ] = "auth",
		[HOSTAPD_UBUS_ASSOC_REQ] = "assoc",
	};
	const char *type = "mgmt";
	struct ubus_event_req ureq = {};
	const u8 *addr;

	if (req->mgmt_frame)
		addr = req->mgmt_frame->sa;
	else
		addr = req->addr;

	ban = avl_find_element(&hapd->ubus.banned, addr, ban, avl);
	if (ban)
		return WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;

	if (!hapd->ubus.obj.has_subscribers)
		return WLAN_STATUS_SUCCESS;

	if (req->type < ARRAY_SIZE(types))
		type = types[req->type];

	blob_buf_init(&b, 0);
	blobmsg_add_macaddr(&b, "address", addr);
	if (req->mgmt_frame)
		blobmsg_add_macaddr(&b, "target", req->mgmt_frame->da);
	if (req->ssi_signal)
		blobmsg_add_u32(&b, "signal", req->ssi_signal);
	blobmsg_add_u32(&b, "freq", hapd->iface->freq);

	if (req->elems) {
		if(req->elems->ht_capabilities)
		{
			struct ieee80211_ht_capabilities *ht_capabilities;
			void *ht_cap, *ht_cap_mcs_set, *mcs_set;


			ht_capabilities = (struct ieee80211_ht_capabilities*) req->elems->ht_capabilities;
			ht_cap = blobmsg_open_table(&b, "ht_capabilities");
			blobmsg_add_u16(&b, "ht_capabilities_info", ht_capabilities->ht_capabilities_info);
			ht_cap_mcs_set = blobmsg_open_table(&b, "supported_mcs_set");
			blobmsg_add_u16(&b, "a_mpdu_params", ht_capabilities->a_mpdu_params);
			blobmsg_add_u16(&b, "ht_extended_capabilities", ht_capabilities->ht_extended_capabilities);
			blobmsg_add_u32(&b, "tx_bf_capability_info", ht_capabilities->tx_bf_capability_info);
			blobmsg_add_u16(&b, "asel_capabilities", ht_capabilities->asel_capabilities);
			mcs_set = blobmsg_open_array(&b, "supported_mcs_set");
			for (int i = 0; i < 16; i++) {
				blobmsg_add_u16(&b, NULL, (u16) ht_capabilities->supported_mcs_set[i]);
			}
			blobmsg_close_array(&b, mcs_set);
			blobmsg_close_table(&b, ht_cap_mcs_set);
			blobmsg_close_table(&b, ht_cap);
		}
		if(req->elems->vht_capabilities)
		{
			struct ieee80211_vht_capabilities *vht_capabilities;
			void *vht_cap, *vht_cap_mcs_set;

			vht_capabilities = (struct ieee80211_vht_capabilities*) req->elems->vht_capabilities;
			vht_cap = blobmsg_open_table(&b, "vht_capabilities");
			blobmsg_add_u32(&b, "vht_capabilities_info", vht_capabilities->vht_capabilities_info);
			vht_cap_mcs_set = blobmsg_open_table(&b, "vht_supported_mcs_set");
			blobmsg_add_u16(&b, "rx_map", vht_capabilities->vht_supported_mcs_set.rx_map);
			blobmsg_add_u16(&b, "rx_highest", vht_capabilities->vht_supported_mcs_set.rx_highest);
			blobmsg_add_u16(&b, "tx_map", vht_capabilities->vht_supported_mcs_set.tx_map);
			blobmsg_add_u16(&b, "tx_highest", vht_capabilities->vht_supported_mcs_set.tx_highest);
			blobmsg_close_table(&b, vht_cap_mcs_set);
			blobmsg_close_table(&b, vht_cap);
		}
	}

	if (!hapd->ubus.notify_response) {
		ubus_notify(ctx, &hapd->ubus.obj, type, b.head, -1);
		return WLAN_STATUS_SUCCESS;
	}

	if (ubus_notify_async(ctx, &hapd->ubus.obj, type, b.head, &ureq.nreq))
		return WLAN_STATUS_SUCCESS;

	ureq.nreq.status_cb = ubus_event_cb;
	ubus_complete_request(ctx, &ureq.nreq.req, 100);

	if (ureq.resp)
		return ureq.resp;

	return WLAN_STATUS_SUCCESS;
}

void hostapd_ubus_notify(struct hostapd_data *hapd, const char *type, const u8 *addr)
{
	if (!hapd->ubus.obj.has_subscribers)
		return;

	if (!addr)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_macaddr(&b, "address", addr);

	blobmsg_add_hapd_id(&b, hapd);

	ubus_notify(ctx, &hapd->ubus.obj, type, b.head, -1);
}

static void blobmsg_add_iface_state(struct blob_buf *buff,
		struct hostapd_iface *iface, int cur, int old)
{
	blobmsg_add_u32(buff, "oldstate_num", old);
	blobmsg_add_string(buff, "oldstate", hostapd_state_text(old));
	blobmsg_add_u32(buff, "state_num", cur);
	blobmsg_add_string(buff, "state", hostapd_state_text(cur));
}
static void blobmsg_add_iface_channel(struct blob_buf *buff,
		struct hostapd_iface *iface)
{
	struct hostapd_config *conf = iface->conf;
	int width = 20;
	void *chan;

	if (!iface->freq) {
		return;
	}

	chan = blobmsg_open_table(buff, "channel");

	blobmsg_add_u32(buff, "freq", iface->freq);
	blobmsg_add_u32(buff, "channel", conf->channel);
	blobmsg_add_u8(buff, "ht", conf->ieee80211n);
	blobmsg_add_u8(buff, "vht", conf->ieee80211ac);
	blobmsg_add_u32(buff, "secondary_channel", conf->secondary_channel);
	switch (conf->vht_oper_chwidth) {
		case CHANWIDTH_USE_HT:
			width = conf->secondary_channel ? 40 : 20;
			break;
		case CHANWIDTH_80MHZ:
			width = 80;
			break;
		case CHANWIDTH_160MHZ:
			width = 160;
			break;
		case CHANWIDTH_80P80MHZ:
			width = 8080;
			break;
	}
	blobmsg_add_u32(buff, "width", width);
	blobmsg_add_u32(buff, "center_idx0", conf->vht_oper_centr_freq_seg0_idx);
	blobmsg_add_u32(buff, "center_idx1", conf->vht_oper_centr_freq_seg1_idx);
	blobmsg_add_u8(buff, "is_dfs", ieee80211_is_dfs(iface->freq, iface->hw_features, iface->num_hw_features));
	blobmsg_close_table(buff, chan);
}

void hostapd_ubus_notify_beacon_report(
	struct hostapd_data *hapd, const u8 *addr, u8 token, u8 rep_mode,
	struct rrm_measurement_beacon_report *rep, size_t len)
{
	if (!hapd->ubus.obj.has_subscribers)
		return;

	if (!addr || !rep)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_macaddr(&b, "address", addr);
	blobmsg_add_u16(&b, "op-class", rep->op_class);
	blobmsg_add_u16(&b, "channel", rep->channel);
	blobmsg_add_u64(&b, "start-time", rep->start_time);
	blobmsg_add_u16(&b, "duration", rep->duration);
	blobmsg_add_u16(&b, "report-info", rep->report_info);
	blobmsg_add_u16(&b, "rcpi", rep->rcpi);
	blobmsg_add_u16(&b, "rsni", rep->rsni);
	blobmsg_add_macaddr(&b, "bssid", rep->bssid);
	blobmsg_add_u16(&b, "antenna-id", rep->antenna_id);
	blobmsg_add_u16(&b, "parent-tsf", rep->parent_tsf);

	ubus_notify(ctx, &hapd->ubus.obj, "beacon-report", b.head, -1);
}

void hostapd_ubus_event_iface_state(struct hostapd_iface *iface, int s)
{
	struct hostapd_data *hapd = iface->bss[0];

	if (!hostapd_ubus_init())
		return;

	// after 21.02 we don't need to recreate ubus obj for iface
	// because hostapd running as daemon and it will be memory corruption
	// hostapd_ubus_add_iface(iface);

	if (iface->state == s) {
		return;
	}

	blob_buf_init(&b, 0);
	if (hapd && hapd->conf->uci_device)
		blobmsg_add_string(&b, "device", hapd->conf->uci_device);
	if (iface->ubus.obj.id)
		blobmsg_add_string(&b, "uobject", iface->ubus.obj.name);
	blobmsg_add_iface_state(&b, iface, s, iface->state);
	blobmsg_add_iface_channel(&b, iface);
	ubus_send_event(ctx, "hostapd.iface_state", b.head);
}

void hostapd_ubus_event_ch_switch(struct hostapd_iface *iface)
{
	struct hostapd_data *hapd = iface->bss[0];

	if (!hostapd_ubus_init())
		return;
	hostapd_ubus_add_iface(iface);
	blob_buf_init(&b, 0);
	if (hapd && hapd->conf->uci_device)
		blobmsg_add_string(&b, "device", hapd->conf->uci_device);
	if (iface->ubus.obj.id)
		blobmsg_add_string(&b, "uobject", iface->ubus.obj.name);
	blobmsg_add_iface_state(&b, iface, iface->state, iface->state);
	blobmsg_add_iface_channel(&b, iface);
	ubus_send_event(ctx, "hostapd.iface_state", b.head);
}

static void
blobmsg_add_sta_data(struct blob_buf *buf, const char *name,
		struct sta_info *sta,
		const struct hostap_sta_driver_data *data)
{
	u64 bytes;
	void *tbl = blobmsg_open_table(buf, name);

	blobmsg_add_u32(buf, "rx_packets", data->rx_packets);
	blobmsg_add_u32(buf, "tx_packets", data->tx_packets);

	if (data->bytes_64bit)
		bytes = data->rx_bytes;
	else
		bytes = ((u64) sta->last_rx_bytes_hi << 32) |
			sta->last_rx_bytes_lo;
	blobmsg_add_u64(buf, "rx_bytes", bytes);
	if (data->bytes_64bit)
		bytes = data->tx_bytes;
	else
		bytes = ((u64) sta->last_tx_bytes_hi << 32) |
			sta->last_tx_bytes_lo;
	blobmsg_add_u64(buf, "tx_bytes", bytes);
	blobmsg_add_double(buf, "rssi", data->last_ack_rssi);
	blobmsg_add_double(buf, "signal", data->signal);

	blobmsg_close_table(buf, tbl);
}
static void
blobmsg_add_reltime(struct blob_buf *buf, const char *name,
		const struct os_reltime *reltime)
{
	blobmsg_add_u32(buf, name, reltime->sec);
}
static void
blobmsg_add_session_id(struct blob_buf *buf, const char *name,
		struct sta_info *sta)
{
	blobmsg_printf(buf, name, "%016llX",
			(unsigned long long) sta->acct_session_id);
}
static void
blobmsg_add_station_accounting(struct blob_buf *buf,
		const char *name,
		struct sta_info *sta,
		const struct hostap_sta_driver_data *data,
		const struct os_reltime *session_time,
		int cause)
{
	void *tbl = blobmsg_open_table(buf, name);
	blobmsg_add_macaddr(buf, "address", sta->addr);
	blobmsg_add_session_id(buf, "session_id", sta);
	if(data)
		blobmsg_add_sta_data(buf, "accounting", sta, data);
	if(session_time)
		blobmsg_add_reltime(buf, "session_time", session_time);
	if (sta->identity)
		blobmsg_add_string(buf, "identity", sta->identity);
	if (cause > 0)
		blobmsg_add_u32(buf, "terminate_cause", cause);
	blobmsg_close_table(buf, tbl);
}
static void hostapd_ubus_event_sta_account(struct hostapd_data *hapd,
		struct sta_info *sta, const char *status,
		const struct hostap_sta_driver_data *data,
		const struct os_reltime *session_time,
		int cause)
{
	void *arr;

	if (!ctx)
		return;
	blob_buf_init(&b, 0);

	arr = blobmsg_open_array(&b, "clients");
	blobmsg_add_station_accounting(&b, NULL, sta, data, session_time, cause);
	blobmsg_close_array(&b, arr);
	blobmsg_add_u32(&b, "freq", hapd->iface->freq);

	blobmsg_add_hapd_id(&b, hapd);
	ubus_notify(ctx, &hapd->ubus.obj, status, b.head, -1);
}
void hostapd_ubus_event_sta_account_start(struct hostapd_data *hapd,
		struct sta_info *sta)
{
	if (sta->acct_session_started || !hapd->ubus.obj.has_subscribers)
		return;
#ifdef CONFIG_NO_ACCOUNTING
	os_get_reltime(&sta->acct_session_start);
	sta->last_rx_bytes_hi = 0;
	sta->last_rx_bytes_lo = 0;
	sta->last_tx_bytes_hi = 0;
	sta->last_tx_bytes_lo = 0;
	hostapd_drv_sta_clear_stats(hapd, sta->addr);
#endif
	sta->acct_session_started = 1;
	hostapd_ubus_event_sta_account(hapd, sta, "start", NULL, NULL, 0);
}
void hostapd_ubus_event_sta_account_stop(struct hostapd_data *hapd,
		struct sta_info *sta)
{
	struct hostap_sta_driver_data data, *pdata = NULL;
	struct os_reltime now_r, diff;
	int cause = sta->acct_terminate_cause;

	if (!sta->acct_session_started || !hapd->ubus.obj.has_subscribers)
		return;
	sta->acct_session_started = 0;
	if (!ctx)
		return;
	if (eloop_terminated())
		cause = RADIUS_ACCT_TERMINATE_CAUSE_ADMIN_REBOOT;
	os_get_reltime(&now_r);
	os_reltime_sub(&now_r, &sta->acct_session_start, &diff);
	if (accounting_sta_update_stats(hapd, sta, &data) == 0)
		pdata = &data;
	hostapd_ubus_event_sta_account(hapd, sta, "stop", pdata, &diff, cause);
}
struct ubus_sta_acct_counter {
	struct blob_buf *buf;
	int counter;
	struct os_reltime now;
};
static int hostapd_ubus_event_sta_account_interim(struct hostapd_data *hapd,
		struct sta_info *sta, void *ctx)
{
	struct ubus_sta_acct_counter *counter = ctx;
	struct os_reltime diff;
	struct hostap_sta_driver_data data, *pdata = NULL;

	if (!sta->acct_session_started)
		return 0;
	os_reltime_sub(&counter->now, &sta->acct_session_start, &diff);
	if (accounting_sta_update_stats(hapd, sta, &data) == 0)
		pdata = &data;
	blobmsg_add_station_accounting(counter->buf, NULL, sta, pdata, &diff, 0);
	++counter->counter;
}
static void hostapd_ubus_accounting_interim(struct hostapd_data *hapd,
		struct sta_info *sta)
{
	struct ubus_sta_acct_counter counter = { &b, 0 };
	void *arr;

	if (!hapd->ubus.obj.has_subscribers)
		return;
	blob_buf_init(&b, 0);

	os_get_reltime(&counter.now);
	blobmsg_add_u32(&b, "freq", hapd->iface->freq);
	blobmsg_add_hapd_id(&b, hapd);
	arr = blobmsg_open_array(&b, "clients");

	if (sta != NULL)
		hostapd_ubus_event_sta_account_interim(hapd, sta, &counter);
	else
		ap_for_each_sta(hapd, hostapd_ubus_event_sta_account_interim, &counter);
	blobmsg_close_array(&b, arr);
	if (counter.counter > 0)
		ubus_notify(ctx, &hapd->ubus.obj, "interim", b.head, -1);
}
static void hostapd_ubus_accounting_interim_update(void *eloop_ctx,
		void *timer_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	hostapd_ubus_accounting_interim(hapd, NULL);
	hostapd_ubus_accounting_init(hapd);
}

#ifdef CONFIG_NO_ACCOUNTING
int accounting_sta_update_stats(struct hostapd_data *hapd,
					   struct sta_info *sta,
					   struct hostap_sta_driver_data *data)
{
	if (hostapd_drv_read_sta_data(hapd, data, sta->addr))
		return -1;

	if (!data->bytes_64bit) {
		/* Extend 32-bit counters from the driver to 64-bit counters */
		if (sta->last_rx_bytes_lo > data->rx_bytes)
			sta->last_rx_bytes_hi++;
		sta->last_rx_bytes_lo = data->rx_bytes;

		if (sta->last_tx_bytes_lo > data->tx_bytes)
			sta->last_tx_bytes_hi++;
		sta->last_tx_bytes_lo = data->tx_bytes;
	}

	hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_RADIUS,
			   HOSTAPD_LEVEL_DEBUG,
			   "updated TX/RX stats: rx_bytes=%llu [%u:%u] tx_bytes=%llu [%u:%u] bytes_64bit=%d",
			   data->rx_bytes, sta->last_rx_bytes_hi,
			   sta->last_rx_bytes_lo,
			   data->tx_bytes, sta->last_tx_bytes_hi,
			   sta->last_tx_bytes_lo,
			   data->bytes_64bit);

	return 0;
}
int accounting_sta_get_id(struct hostapd_data *hapd, struct sta_info *sta)
{
	/* Copied from radius_gen_session_id */
	return os_get_random((u8 *) &sta->acct_session_id,
			sizeof(sta->acct_session_id));
}
#endif

void hostapd_ubus_notify_radar_detected(struct hostapd_iface *iface, int frequency,
					int chan_width, int cf1, int cf2)
{
	struct hostapd_data *hapd;
	int i;

	blob_buf_init(&b, 0);
	blobmsg_add_u16(&b, "frequency", frequency);
	blobmsg_add_u16(&b, "width", chan_width);
	blobmsg_add_u16(&b, "center1", cf1);
	blobmsg_add_u16(&b, "center2", cf2);

	for (i = 0; i < iface->num_bss; i++) {
		hapd = iface->bss[i];
		ubus_notify(ctx, &hapd->ubus.obj, "radar-detected", b.head, -1);
	}
}

#ifdef CONFIG_WNM_AP
static void hostapd_ubus_notify_bss_transition_add_candidate_list(
	const u8 *candidate_list, u16 candidate_list_len)
{
	char *cl_str;
	int i;

	if (candidate_list_len == 0)
		return;

	cl_str = blobmsg_alloc_string_buffer(&b, "candidate-list", candidate_list_len * 2 + 1);
	for (i = 0; i < candidate_list_len; i++)
		snprintf(&cl_str[i*2], 3, "%02X", candidate_list[i]);
	blobmsg_add_string_buffer(&b);

}
#endif

void hostapd_ubus_notify_bss_transition_response(
	struct hostapd_data *hapd, const u8 *addr, u8 dialog_token, u8 status_code,
	u8 bss_termination_delay, const u8 *target_bssid,
	const u8 *candidate_list, u16 candidate_list_len)
{
#ifdef CONFIG_WNM_AP
	u16 i;

	if (!hapd->ubus.obj.has_subscribers)
		return;

	if (!addr)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_macaddr(&b, "address", addr);
	blobmsg_add_u8(&b, "dialog-token", dialog_token);
	blobmsg_add_u8(&b, "status-code", status_code);
	blobmsg_add_u8(&b, "bss-termination-delay", bss_termination_delay);
	if (target_bssid)
		blobmsg_add_macaddr(&b, "target-bssid", target_bssid);

	hostapd_ubus_notify_bss_transition_add_candidate_list(candidate_list, candidate_list_len);

	ubus_notify(ctx, &hapd->ubus.obj, "bss-transition-response", b.head, -1);
#endif
}

int hostapd_ubus_notify_bss_transition_query(
	struct hostapd_data *hapd, const u8 *addr, u8 dialog_token, u8 reason,
	const u8 *candidate_list, u16 candidate_list_len)
{
#ifdef CONFIG_WNM_AP
	struct ubus_event_req ureq = {};
	char *cl_str;
	u16 i;

	if (!hapd->ubus.obj.has_subscribers)
		return 0;

	if (!addr)
		return 0;

	blob_buf_init(&b, 0);
	blobmsg_add_macaddr(&b, "address", addr);
	blobmsg_add_u8(&b, "dialog-token", dialog_token);
	blobmsg_add_u8(&b, "reason", reason);
	hostapd_ubus_notify_bss_transition_add_candidate_list(candidate_list, candidate_list_len);

	if (!hapd->ubus.notify_response) {
		ubus_notify(ctx, &hapd->ubus.obj, "bss-transition-query", b.head, -1);
		return 0;
	}

	if (ubus_notify_async(ctx, &hapd->ubus.obj, "bss-transition-query", b.head, &ureq.nreq))
		return 0;

	ureq.nreq.status_cb = ubus_event_cb;
	ubus_complete_request(ctx, &ureq.nreq.req, 100);

	return ureq.resp;
#endif
}
