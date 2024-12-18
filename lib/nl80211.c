/*
Copyright 2021 Jo-Philipp Wich <jo@mein.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <math.h>
#include <assert.h>
#include <fcntl.h>
#include <poll.h>

#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include <linux/nl80211.h>
#include <linux/ieee80211.h>
#include <linux/mac80211_hwsim.h>
#include <libubox/uloop.h>

#include "ucode/module.h"
#include "ucode/platform.h"

#define DIV_ROUND_UP(n, d)      (((n) + (d) - 1) / (d))

#define err_return(code, ...) do { set_error(vm, code, __VA_ARGS__); return NULL; } while(0)

/* Modified downstream nl80211.h headers may disable certain unsupported
 * attributes by setting the corresponding defines to 0x10000 without having
 * to patch the attribute dictionaries within this file. */

#define NL80211_ATTR_NOT_IMPLEMENTED 0x10000

#define NL80211_CMDS_BITMAP_SIZE	DIV_ROUND_UP(NL80211_CMD_MAX + 1, 32)

__attribute__((format(printf, 3, 4))) static void
set_error(uc_vm_t *vm, int errcode, const char *fmt, ...)
{
	uc_value_t *last_error;
	va_list ap;
	char *s;

	if (errcode == -(NLE_MAX + 1))
		return;

	last_error = uc_vm_registry_get(vm, "nl80211.error");

	if (!last_error) {
		last_error = ucv_array_new_length(vm, 2);
		uc_vm_registry_set(vm, "nl80211.error", last_error);
	}

	ucv_array_set(last_error, 0, ucv_int64_new(errcode));

	if (fmt) {
		va_start(ap, fmt);
		xvasprintf(&s, fmt, ap);
		va_end(ap);

		ucv_array_set(last_error, 1, ucv_string_new(s));
		free(s);
	}
	else {
		ucv_array_set(last_error, 1, NULL);
	}
}

typedef struct {
	uc_resource_t resource;
	uint32_t cmds[NL80211_CMDS_BITMAP_SIZE];
	uc_value_t *callback;
} uc_nl_listener_t;

static bool
uc_nl_parse_u32(uc_value_t *val, uint32_t *n)
{
	uint64_t u;

	u = ucv_to_unsigned(val);

	if (errno != 0 || u > UINT32_MAX)
		return false;

	*n = (uint32_t)u;

	return true;
}

static bool
uc_nl_parse_s32(uc_value_t *val, uint32_t *n)
{
	int64_t i;

	i = ucv_to_integer(val);

	if (errno != 0 || i < INT32_MIN || i > INT32_MAX)
		return false;

	*n = (uint32_t)i;

	return true;
}

static bool
uc_nl_parse_u64(uc_value_t *val, uint64_t *n)
{
	*n = ucv_to_unsigned(val);

	return (errno == 0);
}

static bool
uc_nl_parse_ipaddr(uc_vm_t *vm, uc_value_t *val, struct in_addr *in)
{
	char *s = ucv_to_string(vm, val);
	bool valid = true;

	if (!s)
		return false;

	valid = (inet_pton(AF_INET, s, in) == 1);

	free(s);

	return valid;
}

typedef enum {
	DT_FLAG,
	DT_BOOL,
	DT_U8,
	DT_S8,
	DT_U16,
	DT_U32,
	DT_S32,
	DT_U64,
	DT_STRING,
	DT_NETDEV,
	DT_LLADDR,
	DT_INADDR,
	DT_NESTED,
	DT_HT_MCS,
	DT_HT_CAP,
	DT_VHT_MCS,
	DT_HE_MCS,
	DT_IE,
} uc_nl_attr_datatype_t;

enum {
	DF_NO_SET = (1 << 0),
	DF_MULTIPLE = (1 << 1),
	DF_AUTOIDX = (1 << 2),
	DF_TYPEIDX = (1 << 3),
	DF_OFFSET1 = (1 << 4),
	DF_ARRAY = (1 << 5),
	DF_BINARY = (1 << 6),
	DF_RELATED = (1 << 7),
	DF_REPEATED = (1 << 8),
};

typedef struct uc_nl_attr_spec {
	size_t attr;
	const char *key;
	uc_nl_attr_datatype_t type;
	uint32_t flags;
	const void *auxdata;
} uc_nl_attr_spec_t;

typedef struct uc_nl_nested_spec {
	size_t headsize;
	size_t nattrs;
	const uc_nl_attr_spec_t attrs[];
} uc_nl_nested_spec_t;

#define SIZE(type) (void *)(uintptr_t)sizeof(struct type)
#define MEMBER(type, field) (void *)(uintptr_t)offsetof(struct type, field)
#define ATTRID(id) (void *)(uintptr_t)(id)

static const uc_nl_nested_spec_t nl80211_cqm_nla = {
	.headsize = 0,
	.nattrs = 5,
	.attrs = {
		{ NL80211_ATTR_CQM_PKT_LOSS_EVENT, "cqm_pkt_loss_event", DT_U32, 0, NULL },
		{ NL80211_ATTR_CQM_RSSI_HYST, "cqm_rssi_hyst", DT_U32, 0, NULL },
		{ NL80211_ATTR_CQM_RSSI_LEVEL, "cqm_rssi_level", DT_S32, 0, NULL },
		{ NL80211_ATTR_CQM_RSSI_THOLD, "cqm_rssi_thold", DT_U32, 0, NULL },
		{ NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT, "cqm_rssi_threshold_event", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_ftm_responder_stats_nla = {
	.headsize = 0,
	.nattrs = 9,
	.attrs = {
		{ NL80211_FTM_STATS_SUCCESS_NUM, "success_num", DT_U32, 0, NULL },
		{ NL80211_FTM_STATS_PARTIAL_NUM, "partial_num", DT_U32, 0, NULL },
		{ NL80211_FTM_STATS_FAILED_NUM, "failed_num", DT_U32, 0, NULL },
		{ NL80211_FTM_STATS_ASAP_NUM, "asap_num", DT_U32, 0, NULL },
		{ NL80211_FTM_STATS_NON_ASAP_NUM, "non_asap_num", DT_U32, 0, NULL },
		{ NL80211_FTM_STATS_TOTAL_DURATION_MSEC, "total_duration_msec", DT_U64, 0, NULL },
		{ NL80211_FTM_STATS_UNKNOWN_TRIGGERS_NUM, "unknown_triggers_num", DT_U32, 0, NULL },
		{ NL80211_FTM_STATS_RESCHEDULE_REQUESTS_NUM, "reschedule_requests_num", DT_U32, 0, NULL },
		{ NL80211_FTM_STATS_OUT_OF_WINDOW_TRIGGERS_NUM, "out_of_window_triggers_num", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_ifcomb_limit_types_nla = {
	.headsize = 0,
	.nattrs = 12,
	.attrs = {
		{ 1, "ibss", DT_FLAG, 0, NULL },
		{ 2, "managed", DT_FLAG, 0, NULL },
		{ 3, "ap", DT_FLAG, 0, NULL },
		{ 4, "ap_vlan", DT_FLAG, 0, NULL },
		{ 5, "wds", DT_FLAG, 0, NULL },
		{ 6, "monitor", DT_FLAG, 0, NULL },
		{ 7, "mesh_point", DT_FLAG, 0, NULL },
		{ 8, "p2p_client", DT_FLAG, 0, NULL },
		{ 9, "p2p_go", DT_FLAG, 0, NULL },
		{ 10, "p2p_device", DT_FLAG, 0, NULL },
		{ 11, "outside_bss_context", DT_FLAG, 0, NULL },
		{ 12, "nan", DT_FLAG, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_ifcomb_limits_nla = {
	.headsize = 0,
	.nattrs = 2,
	.attrs = {
		{ NL80211_IFACE_LIMIT_TYPES, "types", DT_NESTED, 0, &nl80211_ifcomb_limit_types_nla },
		{ NL80211_IFACE_LIMIT_MAX, "max", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_ifcomb_nla = {
	.headsize = 0,
	.nattrs = 5,
	.attrs = {
		{ NL80211_IFACE_COMB_LIMITS, "limits", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_ifcomb_limits_nla },
		{ NL80211_IFACE_COMB_MAXNUM, "maxnum", DT_U32, 0, NULL },
		{ NL80211_IFACE_COMB_STA_AP_BI_MATCH, "sta_ap_bi_match", DT_FLAG, 0, NULL },
		{ NL80211_IFACE_COMB_NUM_CHANNELS, "num_channels", DT_U32, 0, NULL },
		{ NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS, "radar_detect_widths", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_ftm_responder_nla = {
	.headsize = 0,
	.nattrs = 3,
	.attrs = {
		{ NL80211_FTM_RESP_ATTR_ENABLED, "enabled", DT_FLAG, 0, NULL },
		{ NL80211_FTM_RESP_ATTR_LCI, "lci", DT_STRING, DF_BINARY, NULL },
		{ NL80211_FTM_RESP_ATTR_CIVICLOC, "civicloc", DT_STRING, DF_BINARY, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_keys_nla = {
	.headsize = 0,
	.nattrs = 4,
	.attrs = {
		{ NL80211_KEY_DEFAULT, "default", DT_FLAG, 0, NULL },
		{ NL80211_KEY_IDX, "idx", DT_U8, 0, NULL },
		{ NL80211_KEY_CIPHER, "cipher", DT_U32, 0, NULL },
		{ NL80211_KEY_DATA, "data", DT_STRING, DF_BINARY, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_mesh_params_nla = {
	.headsize = 0,
	.nattrs = 29,
	.attrs = {
		{ NL80211_MESHCONF_RETRY_TIMEOUT, "retry_timeout", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_CONFIRM_TIMEOUT, "confirm_timeout", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_HOLDING_TIMEOUT, "holding_timeout", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_MAX_PEER_LINKS, "max_peer_links", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_MAX_RETRIES, "max_retries", DT_U8, 0, NULL },
		{ NL80211_MESHCONF_TTL, "ttl", DT_U8, 0, NULL },
		{ NL80211_MESHCONF_ELEMENT_TTL, "element_ttl", DT_U8, 0, NULL },
		{ NL80211_MESHCONF_AUTO_OPEN_PLINKS, "auto_open_plinks", DT_BOOL, 0, NULL },
		{ NL80211_MESHCONF_HWMP_MAX_PREQ_RETRIES, "hwmp_max_preq_retries", DT_U8, 0, NULL },
		{ NL80211_MESHCONF_PATH_REFRESH_TIME, "path_refresh_time", DT_U32, 0, NULL },
		{ NL80211_MESHCONF_MIN_DISCOVERY_TIMEOUT, "min_discovery_timeout", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_HWMP_ACTIVE_PATH_TIMEOUT, "hwmp_active_path_timeout", DT_U32, 0, NULL },
		{ NL80211_MESHCONF_HWMP_PREQ_MIN_INTERVAL, "hwmp_preq_min_interval", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_HWMP_NET_DIAM_TRVS_TIME, "hwmp_net_diam_trvs_time", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_HWMP_ROOTMODE, "hwmp_rootmode", DT_U8, 0, NULL },
		{ NL80211_MESHCONF_HWMP_RANN_INTERVAL, "hwmp_rann_interval", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_GATE_ANNOUNCEMENTS, "gate_announcements", DT_U8, 0, NULL },
		{ NL80211_MESHCONF_FORWARDING, "forwarding", DT_BOOL, 0, NULL },
		{ NL80211_MESHCONF_SYNC_OFFSET_MAX_NEIGHBOR, "sync_offset_max_neighbor", DT_U32, 0, NULL },
		{ NL80211_MESHCONF_RSSI_THRESHOLD, "rssi_threshold", DT_S32, 0, NULL },
		{ NL80211_MESHCONF_HWMP_PATH_TO_ROOT_TIMEOUT, "hwmp_path_to_root_timeout", DT_U32, 0, NULL },
		{ NL80211_MESHCONF_HWMP_ROOT_INTERVAL, "hwmp_root_interval", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_HWMP_CONFIRMATION_INTERVAL, "hwmp_confirmation_interval", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_POWER_MODE, "power_mode", DT_U32, 0, NULL },
		{ NL80211_MESHCONF_AWAKE_WINDOW, "awake_window", DT_U16, 0, NULL },
		{ NL80211_MESHCONF_PLINK_TIMEOUT, "plink_timeout", DT_U32, 0, NULL },
		{ NL80211_MESHCONF_CONNECTED_TO_GATE, "connected_to_gate", DT_BOOL, 0, NULL },
		{ NL80211_MESHCONF_NOLEARN, "nolearn", DT_BOOL, 0, NULL },
		{ NL80211_MESHCONF_CONNECTED_TO_AS, "connected_to_as", DT_BOOL, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_mesh_setup_nla = {
	.headsize = 0,
	.nattrs = 1,
	.attrs = {
		{ NL80211_MESH_SETUP_ENABLE_VENDOR_SYNC, "enable_vendor_sync", DT_BOOL, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_mntr_flags_nla = {
	.headsize = 0,
	.nattrs = 7,
	.attrs = {
		{ NL80211_MNTR_FLAG_FCSFAIL, "fcsfail", DT_FLAG, 0, NULL },
		{ NL80211_MNTR_FLAG_PLCPFAIL, "plcpfail", DT_FLAG, 0, NULL },
		{ NL80211_MNTR_FLAG_CONTROL, "control", DT_FLAG, 0, NULL },
		{ NL80211_MNTR_FLAG_OTHER_BSS, "other_bss", DT_FLAG, 0, NULL },
		{ NL80211_MNTR_FLAG_COOK_FRAMES, "cook_frames", DT_FLAG, 0, NULL },
		{ NL80211_MNTR_FLAG_ACTIVE, "active", DT_FLAG, 0, NULL },
		{ NL80211_MNTR_FLAG_SKIP_TX, "skip_tx", DT_FLAG, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_nan_func_srf_nla = {
	.headsize = 0,
	.nattrs = 4,
	.attrs = {
		{ NL80211_NAN_SRF_INCLUDE, "include", DT_FLAG, 0, NULL },
		{ NL80211_NAN_SRF_BF_IDX, "bf_idx", DT_U8, 0, NULL },
		{ NL80211_NAN_SRF_BF, "bf", DT_STRING, DF_BINARY, NULL },
		{ NL80211_NAN_SRF_MAC_ADDRS, "mac_addrs", DT_LLADDR, DF_MULTIPLE|DF_AUTOIDX, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_nan_func_nla = {
	.headsize = 0,
	.nattrs = 16,
	.attrs = {
		{ NL80211_NAN_FUNC_TYPE, "type", DT_U8, 0, NULL },
		{ NL80211_NAN_FUNC_SERVICE_ID, "service_id", DT_STRING, DF_BINARY, NULL },
		{ NL80211_NAN_FUNC_PUBLISH_TYPE, "publish_type", DT_U8, 0, NULL },
		{ NL80211_NAN_FUNC_PUBLISH_BCAST, "publish_bcast", DT_FLAG, 0, NULL },
		{ NL80211_NAN_FUNC_SUBSCRIBE_ACTIVE, "subscribe_active", DT_FLAG, 0, NULL },
		{ NL80211_NAN_FUNC_FOLLOW_UP_ID, "follow_up_id", DT_U8, 0, NULL },
		{ NL80211_NAN_FUNC_FOLLOW_UP_REQ_ID, "follow_up_req_id", DT_U8, 0, NULL },
		{ NL80211_NAN_FUNC_FOLLOW_UP_DEST, "follow_up_dest", DT_LLADDR, 0, NULL },
		{ NL80211_NAN_FUNC_CLOSE_RANGE, "close_range", DT_FLAG, 0, NULL },
		{ NL80211_NAN_FUNC_TTL, "ttl", DT_U32, 0, NULL },
		{ NL80211_NAN_FUNC_SERVICE_INFO, "service_info", DT_STRING, 0, NULL },
		{ NL80211_NAN_FUNC_SRF, "srf", DT_NESTED, 0, &nl80211_nan_func_srf_nla },
		{ NL80211_NAN_FUNC_RX_MATCH_FILTER, "rx_match_filter", DT_STRING, DF_MULTIPLE|DF_AUTOIDX, NULL },
		{ NL80211_NAN_FUNC_TX_MATCH_FILTER, "tx_match_filter", DT_STRING, DF_MULTIPLE|DF_AUTOIDX, NULL },
		{ NL80211_NAN_FUNC_INSTANCE_ID, "instance_id", DT_U8, 0, NULL },
		{ NL80211_NAN_FUNC_TERM_REASON, "term_reason", DT_U8, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_peer_measurements_type_ftm_nla = {
	.headsize = 0,
	.nattrs = 13,
	.attrs = {
		{ NL80211_PMSR_FTM_REQ_ATTR_NUM_BURSTS_EXP, "num_bursts_exp", DT_U8, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_BURST_PERIOD, "burst_period", DT_U16, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_NUM_FTMR_RETRIES, "num_ftmr_retries", DT_U8, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_BURST_DURATION, "burst_duration", DT_U8, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST, "ftms_per_burst", DT_U8, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_ASAP, "asap", DT_FLAG, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_REQUEST_CIVICLOC, "request_civicloc", DT_FLAG, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_REQUEST_LCI, "request_lci", DT_FLAG, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_TRIGGER_BASED, "trigger_based", DT_FLAG, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_PREAMBLE, "preamble", DT_U32, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_NON_TRIGGER_BASED, "non_trigger_based", DT_FLAG, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_LMR_FEEDBACK, "lmr_feedback", DT_FLAG, 0, NULL },
		{ NL80211_PMSR_FTM_REQ_ATTR_BSS_COLOR, "bss_color", DT_U8, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_peer_measurements_peers_req_data_nla = {
	.headsize = 0,
	.nattrs = 2,
	.attrs = {
		{ NL80211_PMSR_TYPE_FTM, "ftm", DT_NESTED, 0, &nl80211_peer_measurements_type_ftm_nla },
		{ NL80211_PMSR_REQ_ATTR_GET_AP_TSF, "get_ap_tsf", DT_FLAG, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_peer_measurements_peers_req_nla = {
	.headsize = 0,
	.nattrs = 1,
	.attrs = {
		{ NL80211_PMSR_REQ_ATTR_DATA, "data", DT_NESTED, 0, &nl80211_peer_measurements_peers_req_data_nla },
	}
};

static const uc_nl_nested_spec_t nl80211_peer_measurements_peers_chan_nla = {
	.headsize = 0,
	.nattrs = 4,
	.attrs = {
		{ NL80211_ATTR_WIPHY_FREQ, "freq", DT_U32, 0, NULL },
		{ NL80211_ATTR_CENTER_FREQ1, "center_freq1", DT_U32, 0, NULL },
		{ NL80211_ATTR_CENTER_FREQ2, "center_freq2", DT_U32, 0, NULL },
		{ NL80211_ATTR_CHANNEL_WIDTH, "channel_width", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_peer_measurements_peers_resp_data_nla = {
	.headsize = 0,
	.nattrs = 1,
	.attrs = {
		{ NL80211_PMSR_TYPE_FTM, "ftm", DT_NESTED, 0, &nl80211_peer_measurements_type_ftm_nla },
	}
};

static const uc_nl_nested_spec_t nl80211_peer_measurements_peers_resp_nla = {
	.headsize = 0,
	.nattrs = 5,
	.attrs = {
		{ NL80211_PMSR_RESP_ATTR_STATUS, "status", DT_U32, 0, NULL },
		{ NL80211_PMSR_RESP_ATTR_HOST_TIME, "host_time", DT_U64, 0, NULL },
		{ NL80211_PMSR_RESP_ATTR_AP_TSF, "ap_tsf", DT_U64, 0, NULL },
		{ NL80211_PMSR_RESP_ATTR_FINAL, "final", DT_FLAG, 0, NULL },
		{ NL80211_PMSR_RESP_ATTR_DATA, "data", DT_NESTED, 0, &nl80211_peer_measurements_peers_resp_data_nla },
	}
};

static const uc_nl_nested_spec_t nl80211_peer_measurements_peers_nla = {
	.headsize = 0,
	.nattrs = 4,
	.attrs = {
		{ NL80211_PMSR_PEER_ATTR_ADDR, "addr", DT_LLADDR, 0, NULL },
		{ NL80211_PMSR_PEER_ATTR_REQ, "req", DT_NESTED, 0, &nl80211_peer_measurements_peers_req_nla },
		{ NL80211_PMSR_PEER_ATTR_CHAN, "chan", DT_NESTED, 0, &nl80211_peer_measurements_peers_chan_nla },
		{ NL80211_PMSR_PEER_ATTR_RESP, "resp", DT_NESTED, 0, &nl80211_peer_measurements_peers_resp_nla }
	}
};

static const uc_nl_nested_spec_t nl80211_peer_measurements_nla = {
	.headsize = 0,
	.nattrs = 1,
	.attrs = {
		{ NL80211_PMSR_ATTR_PEERS, "peers", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_peer_measurements_peers_nla },
	}
};

static const uc_nl_nested_spec_t nl80211_reg_rules_nla = {
	.headsize = 0,
	.nattrs = 7,
	.attrs = {
		{ NL80211_ATTR_REG_RULE_FLAGS, "reg_rule_flags", DT_U32, 0, NULL },
		{ NL80211_ATTR_FREQ_RANGE_START, "freq_range_start", DT_U32, 0, NULL },
		{ NL80211_ATTR_FREQ_RANGE_END, "freq_range_end", DT_U32, 0, NULL },
		{ NL80211_ATTR_FREQ_RANGE_MAX_BW, "freq_range_max_bw", DT_U32, 0, NULL },
		{ NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN, "power_rule_max_ant_gain", DT_U32, 0, NULL },
		{ NL80211_ATTR_POWER_RULE_MAX_EIRP, "power_rule_max_eirp", DT_U32, 0, NULL },
		{ NL80211_ATTR_DFS_CAC_TIME, "dfs_cac_time", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_frame_types_nla = {
	.headsize = 0,
	.nattrs = 12,
	.attrs = {
		{ 1, "ibss", DT_U16, DF_MULTIPLE, NULL },
		{ 2, "managed", DT_U16, DF_MULTIPLE, NULL },
		{ 3, "ap", DT_U16, DF_MULTIPLE, NULL },
		{ 4, "ap_vlan", DT_U16, DF_MULTIPLE, NULL },
		{ 5, "wds", DT_U16, DF_MULTIPLE, NULL },
		{ 6, "monitor", DT_U16, DF_MULTIPLE, NULL },
		{ 7, "mesh_point", DT_U16, DF_MULTIPLE, NULL },
		{ 8, "p2p_client", DT_U16, DF_MULTIPLE, NULL },
		{ 9, "p2p_go", DT_U16, DF_MULTIPLE, NULL },
		{ 10, "p2p_device", DT_U16, DF_MULTIPLE, NULL },
		{ 11, "outside_bss_context", DT_U16, DF_MULTIPLE, NULL },
		{ 12, "nan", DT_U16, DF_MULTIPLE, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_sched_scan_match_nla = {
	.headsize = 0,
	.nattrs = 1,
	.attrs = {
		{ NL80211_SCHED_SCAN_MATCH_ATTR_SSID, "ssid", DT_STRING, DF_BINARY, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_sched_scan_plan_nla = {
	.headsize = 0,
	.nattrs = 2,
	.attrs = {
		{ NL80211_SCHED_SCAN_PLAN_INTERVAL, "interval", DT_U32, 0, NULL },
		{ NL80211_SCHED_SCAN_PLAN_ITERATIONS, "iterations", DT_U32, 0, NULL },
	}
};

enum {
	HWSIM_TM_ATTR_CMD = 1,
	HWSIM_TM_ATTR_PS  = 2,
};

static const uc_nl_nested_spec_t nl80211_testdata_nla = {
	.headsize = 0,
	.nattrs = 2,
	.attrs = {
		{ HWSIM_TM_ATTR_CMD, "cmd", DT_U32, 0, NULL },
		{ HWSIM_TM_ATTR_PS, "ps", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_tid_config_nla = {
	.headsize = 0,
	.nattrs = 1,
	.attrs = {
		{ NL80211_TID_CONFIG_ATTR_TIDS, "tids", DT_U16, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_wiphy_bands_freqs_wmm_nla = {
	.headsize = 0,
	.nattrs = 4,
	.attrs = {
		{ NL80211_WMMR_CW_MIN, "cw_min", DT_U16, 0, NULL },
		{ NL80211_WMMR_CW_MAX, "cw_max", DT_U16, 0, NULL },
		{ NL80211_WMMR_AIFSN, "aifsn", DT_U8, 0, NULL },
		{ NL80211_WMMR_TXOP, "txop", DT_U16, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_wiphy_bands_freqs_nla = {
	.headsize = 0,
	.nattrs = 25,
	.attrs = {
		{ NL80211_FREQUENCY_ATTR_FREQ, "freq", DT_U32, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_DISABLED, "disabled", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_NO_IR, "no_ir", DT_FLAG, 0, NULL },
		{ __NL80211_FREQUENCY_ATTR_NO_IBSS, "no_ibss", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_RADAR, "radar", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_MAX_TX_POWER, "max_tx_power", DT_U32, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_DFS_STATE, "dfs_state", DT_U32, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_DFS_TIME, "dfs_time", DT_U32, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_NO_HT40_MINUS, "no_ht40_minus", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_NO_HT40_PLUS, "no_ht40_plus", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_NO_80MHZ, "no_80mhz", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_NO_160MHZ, "no_160mhz", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_DFS_CAC_TIME, "dfs_cac_time", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_INDOOR_ONLY, "indoor_only", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_IR_CONCURRENT, "ir_concurrent", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_NO_20MHZ, "no_20mhz", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_NO_10MHZ, "no_10mhz", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_WMM, "wmm", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_wiphy_bands_freqs_wmm_nla },
		{ NL80211_FREQUENCY_ATTR_NO_HE, "no_he", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_OFFSET, "offset", DT_U32, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_1MHZ, "1mhz", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_2MHZ, "2mhz", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_4MHZ, "4mhz", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_8MHZ, "8mhz", DT_FLAG, 0, NULL },
		{ NL80211_FREQUENCY_ATTR_16MHZ, "16mhz", DT_FLAG, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_wiphy_bands_rates_nla = {
	.headsize = 0,
	.nattrs = 2,
	.attrs = {
		{ NL80211_BITRATE_ATTR_RATE, "rate", DT_U32, 0, NULL },
		{ NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE, "2ghz_shortpreamble", DT_FLAG, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_wiphy_bands_iftype_data_nla = {
	.headsize = 0,
	.nattrs = 9,
	.attrs = {
		{ NL80211_BAND_IFTYPE_ATTR_IFTYPES, "iftypes", DT_NESTED, 0, &nl80211_ifcomb_limit_types_nla },
		{ NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, "he_cap_mac", DT_U8, DF_ARRAY, NULL },
		{ NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, "he_cap_phy", DT_U8, DF_ARRAY, NULL },
		{ NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET, "he_cap_mcs_set", DT_HE_MCS, DF_RELATED, ATTRID(NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY) },
		{ NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE, "he_cap_ppe", DT_U8, DF_ARRAY, NULL },
		{ NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA, "he_6ghz_capa", DT_U16, 0, NULL },
		{ NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS, "vendor_elems", DT_STRING, DF_BINARY, NULL },
		{ NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC, "eht_cap_mac", DT_U8, DF_ARRAY, NULL },
		{ NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, "eht_cap_phy", DT_U8, DF_ARRAY, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_wiphy_bands_nla = {
	.headsize = 0,
	.nattrs = 11,
	.attrs = {
		{ NL80211_BAND_ATTR_FREQS, "freqs", DT_NESTED, DF_MULTIPLE|DF_TYPEIDX, &nl80211_wiphy_bands_freqs_nla },
		{ NL80211_BAND_ATTR_RATES, "rates", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_wiphy_bands_rates_nla },
		{ NL80211_BAND_ATTR_HT_MCS_SET, "ht_mcs_set", DT_HT_MCS, 0, NULL },
		{ NL80211_BAND_ATTR_HT_CAPA, "ht_capa", DT_U16, 0, NULL },
		{ NL80211_BAND_ATTR_HT_AMPDU_FACTOR, "ht_ampdu_factor", DT_U8, 0, NULL },
		{ NL80211_BAND_ATTR_HT_AMPDU_DENSITY, "ht_ampdu_density", DT_U8, 0, NULL },
		{ NL80211_BAND_ATTR_VHT_MCS_SET, "vht_mcs_set", DT_VHT_MCS, 0, NULL },
		{ NL80211_BAND_ATTR_VHT_CAPA, "vht_capa", DT_U32, 0, NULL },
		{ NL80211_BAND_ATTR_IFTYPE_DATA, "iftype_data", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_wiphy_bands_iftype_data_nla },
		{ NL80211_BAND_ATTR_EDMG_CHANNELS, "edmg_channels", DT_U8, 0, NULL },
		{ NL80211_BAND_ATTR_EDMG_BW_CONFIG, "edmg_bw_config", DT_U8, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_wowlan_triggers_tcp_nla = {
	.headsize = 0,
	.nattrs = 11,
	.attrs = {
		{ NL80211_WOWLAN_TCP_SRC_IPV4, "src_ipv4", DT_INADDR, 0, NULL },
		{ NL80211_WOWLAN_TCP_SRC_PORT, "src_port", DT_U16, 0, NULL },
		{ NL80211_WOWLAN_TCP_DST_IPV4, "dst_ipv4", DT_INADDR, 0, NULL },
		{ NL80211_WOWLAN_TCP_DST_PORT, "dst_port", DT_U16, 0, NULL },
		{ NL80211_WOWLAN_TCP_DST_MAC, "dst_mac", DT_LLADDR, 0, NULL },
		{ NL80211_WOWLAN_TCP_DATA_PAYLOAD, "data_payload", DT_STRING, DF_BINARY, NULL },
		{ NL80211_WOWLAN_TCP_DATA_INTERVAL, "data_interval", DT_U32, 0, NULL },
		{ NL80211_WOWLAN_TCP_WAKE_MASK, "wake_mask", DT_STRING, DF_BINARY, NULL },
		{ NL80211_WOWLAN_TCP_WAKE_PAYLOAD, "wake_payload", DT_STRING, DF_BINARY, NULL },
		{ NL80211_WOWLAN_TCP_DATA_PAYLOAD_SEQ, "data_payload_seq", DT_U32, DF_ARRAY, NULL },
		{ NL80211_WOWLAN_TCP_DATA_PAYLOAD_TOKEN, "data_payload_token", DT_STRING, DF_BINARY, NULL }, /* XXX: struct nl80211_wowlan_tcp_data_token */
	}
};

static const uc_nl_nested_spec_t nl80211_pkt_pattern_nla = {
	.headsize = 0,
	.nattrs = 3,
	.attrs = {
		{ NL80211_PKTPAT_MASK, "mask", DT_STRING, DF_BINARY, NULL },
		{ NL80211_PKTPAT_PATTERN, "pattern", DT_STRING, DF_BINARY, NULL },
		{ NL80211_PKTPAT_OFFSET, "offset", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_wowlan_triggers_nla = {
	.headsize = 0,
	.nattrs = 9,
	.attrs = {
		{ NL80211_WOWLAN_TRIG_ANY, "any", DT_FLAG, 0, NULL },
		{ NL80211_WOWLAN_TRIG_DISCONNECT, "disconnect", DT_FLAG, 0, NULL },
		{ NL80211_WOWLAN_TRIG_MAGIC_PKT, "magic_pkt", DT_FLAG, 0, NULL },
		{ NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE, "gtk_rekey_failure", DT_FLAG, 0, NULL },
		{ NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST, "eap_ident_request", DT_FLAG, 0, NULL },
		{ NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE, "4way_handshake", DT_FLAG, 0, NULL },
		{ NL80211_WOWLAN_TRIG_RFKILL_RELEASE, "rfkill_release", DT_FLAG, 0, NULL },
		{ NL80211_WOWLAN_TRIG_TCP_CONNECTION, "tcp_connection", DT_NESTED, 0, &nl80211_wowlan_triggers_tcp_nla },
		{ NL80211_WOWLAN_TRIG_PKT_PATTERN, "pkt_pattern", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX|DF_OFFSET1, &nl80211_pkt_pattern_nla },
	}
};

static const uc_nl_nested_spec_t nl80211_coalesce_rule_nla = {
	.headsize = 0,
	.nattrs = 3,
	.attrs = {
		{ NL80211_ATTR_COALESCE_RULE_CONDITION, "coalesce_rule_condition", DT_U32, 0, NULL },
		{ NL80211_ATTR_COALESCE_RULE_DELAY, "coalesce_rule_delay", DT_U32, 0, NULL },
		{ NL80211_ATTR_COALESCE_RULE_PKT_PATTERN, "coalesce_rule_pkt_pattern", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX|DF_OFFSET1, &nl80211_pkt_pattern_nla },
	}
};

static const uc_nl_nested_spec_t nl80211_bss_nla = {
	.headsize = 0,
	.nattrs = 12,
	.attrs = {
		{ NL80211_BSS_BSSID, "bssid", DT_LLADDR, 0, NULL },
		{ NL80211_BSS_STATUS, "status", DT_U32, 0, NULL },
		{ NL80211_BSS_LAST_SEEN_BOOTTIME, "last_seen_boottime", DT_U64, 0, NULL },
		{ NL80211_BSS_TSF, "tsf", DT_U64, 0, NULL },
		{ NL80211_BSS_FREQUENCY, "frequency", DT_U32, 0, NULL },
		{ NL80211_BSS_BEACON_INTERVAL, "beacon_interval", DT_U16, 0, NULL },
		{ NL80211_BSS_CAPABILITY, "capability", DT_U16, 0, NULL },
		{ NL80211_BSS_SIGNAL_MBM, "signal_mbm", DT_S32, 0, NULL },
		{ NL80211_BSS_SIGNAL_UNSPEC, "signal_unspec", DT_U8, 0, NULL },
		{ NL80211_BSS_SEEN_MS_AGO, "seen_ms_ago", DT_S32, 0, NULL },
		{ NL80211_BSS_INFORMATION_ELEMENTS, "information_elements", DT_IE, 0, NULL },
		{ NL80211_BSS_BEACON_IES, "beacon_ies", DT_IE, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_sta_info_bitrate_nla = {
	.headsize = 0,
	.nattrs = 22,
	.attrs = {
		{ NL80211_RATE_INFO_BITRATE, "bitrate", DT_U16, 0, NULL },
		{ NL80211_RATE_INFO_BITRATE32, "bitrate32", DT_U32, 0, NULL },
		{ NL80211_RATE_INFO_MCS, "mcs", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_40_MHZ_WIDTH, "40_mhz_width", DT_FLAG, 0, NULL },
		{ NL80211_RATE_INFO_SHORT_GI, "short_gi", DT_FLAG, 0, NULL },
		{ NL80211_RATE_INFO_VHT_MCS, "vht_mcs", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_VHT_NSS, "vht_nss", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_HE_MCS, "he_mcs", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_HE_NSS, "he_nss", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_HE_GI, "he_gi", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_HE_DCM, "he_dcm", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_HE_RU_ALLOC, "he_ru_alloc", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_EHT_MCS, "eht_mcs", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_EHT_NSS, "eht_nss", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_EHT_GI, "eht_gi", DT_U8, 0, NULL },
		{ NL80211_RATE_INFO_40_MHZ_WIDTH, "width_40", DT_FLAG, 0, NULL },
		{ NL80211_RATE_INFO_80_MHZ_WIDTH, "width_80", DT_FLAG, 0, NULL },
		{ NL80211_RATE_INFO_80P80_MHZ_WIDTH, "width_80p80", DT_FLAG, 0, NULL },
		{ NL80211_RATE_INFO_160_MHZ_WIDTH, "width_160", DT_FLAG, 0, NULL },
		{ NL80211_RATE_INFO_320_MHZ_WIDTH, "width_320", DT_FLAG, 0, NULL },
		{ NL80211_RATE_INFO_10_MHZ_WIDTH, "width_10", DT_FLAG, 0, NULL },
		{ NL80211_RATE_INFO_5_MHZ_WIDTH, "width_5", DT_FLAG, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_tid_txq_stats_nla = {
	.headsize = 0,
	.nattrs = 9,
	.attrs = {
		{ NL80211_TXQ_STATS_BACKLOG_BYTES, "backlog_bytes", DT_U32, 0, NULL },
		{ NL80211_TXQ_STATS_BACKLOG_PACKETS, "backlog_packets", DT_U32, 0, NULL },
		{ NL80211_TXQ_STATS_FLOWS, "flows", DT_U32, 0, NULL },
		{ NL80211_TXQ_STATS_DROPS, "drops", DT_U32, 0, NULL },
		{ NL80211_TXQ_STATS_ECN_MARKS, "ecn_marks", DT_U32, 0, NULL },
		{ NL80211_TXQ_STATS_OVERLIMIT, "overlimit", DT_U32, 0, NULL },
		{ NL80211_TXQ_STATS_COLLISIONS, "collisions", DT_U32, 0, NULL },
		{ NL80211_TXQ_STATS_TX_BYTES, "tx_bytes", DT_U32, 0, NULL },
		{ NL80211_TXQ_STATS_TX_PACKETS, "tx_packets", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_tid_stats_nla = {
	.headsize = 0,
	.nattrs = 5,
	.attrs = {
		{ NL80211_TID_STATS_RX_MSDU, "rx_msdu", DT_U64, 0, NULL },
		{ NL80211_TID_STATS_TX_MSDU, "tx_msdu", DT_U64, 0, NULL },
		{ NL80211_TID_STATS_TX_MSDU_RETRIES, "tx_msdu_retries", DT_U64, 0, NULL },
		{ NL80211_TID_STATS_TX_MSDU_FAILED, "tx_msdu_failed", DT_U64, 0, NULL },
		{ NL80211_TID_STATS_TXQ_STATS, "txq_stats", DT_NESTED, 0, &nl80211_tid_txq_stats_nla },
	}
};

static const uc_nl_nested_spec_t nl80211_bss_param_nla = {
	.headsize = 0,
	.nattrs = 5,
	.attrs = {
		{ NL80211_STA_BSS_PARAM_CTS_PROT, "cts_prot", DT_FLAG, 0, NULL },
		{ NL80211_STA_BSS_PARAM_SHORT_PREAMBLE, "short_preamble", DT_FLAG, 0, NULL },
		{ NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME, "short_slot_time", DT_FLAG, 0, NULL },
		{ NL80211_STA_BSS_PARAM_DTIM_PERIOD, "dtim_period", DT_U8, 0, NULL },
		{ NL80211_STA_BSS_PARAM_BEACON_INTERVAL, "beacon_interval", DT_U16, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_sta_info_nla = {
	.headsize = 0,
	.nattrs = 40,
	.attrs = {
		{ NL80211_STA_INFO_INACTIVE_TIME, "inactive_time", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_RX_BYTES, "rx_bytes", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_TX_BYTES, "tx_bytes", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_RX_BYTES64, "rx_bytes64", DT_U64, 0, NULL },
		{ NL80211_STA_INFO_TX_BYTES64, "tx_bytes64", DT_U64, 0, NULL },
		{ NL80211_STA_INFO_RX_PACKETS, "rx_packets", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_TX_PACKETS, "tx_packets", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_BEACON_RX, "beacon_rx", DT_U64, 0, NULL },
		{ NL80211_STA_INFO_SIGNAL, "signal", DT_S8, 0, NULL },
		{ NL80211_STA_INFO_T_OFFSET, "t_offset", DT_U64, 0, NULL },
		{ NL80211_STA_INFO_TX_BITRATE, "tx_bitrate", DT_NESTED, 0, &nl80211_sta_info_bitrate_nla },
		{ NL80211_STA_INFO_RX_BITRATE, "rx_bitrate", DT_NESTED, 0, &nl80211_sta_info_bitrate_nla },
		{ NL80211_STA_INFO_LLID, "llid", DT_U16, 0, NULL },
		{ NL80211_STA_INFO_PLID, "plid", DT_U16, 0, NULL },
		{ NL80211_STA_INFO_PLINK_STATE, "plink_state", DT_U8, 0, NULL },
		{ NL80211_STA_INFO_TX_RETRIES, "tx_retries", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_TX_FAILED, "tx_failed", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_BEACON_LOSS, "beacon_loss", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_RX_DROP_MISC, "rx_drop_misc", DT_U64, 0, NULL },
		{ NL80211_STA_INFO_STA_FLAGS, "sta_flags", DT_U32, DF_ARRAY, NULL },
		{ NL80211_STA_INFO_LOCAL_PM, "local_pm", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_PEER_PM, "peer_pm", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_NONPEER_PM, "nonpeer_pm", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_CHAIN_SIGNAL, "chain_signal", DT_S8, DF_MULTIPLE|DF_AUTOIDX, NULL },
		{ NL80211_STA_INFO_CHAIN_SIGNAL_AVG, "chain_signal_avg", DT_S8, DF_MULTIPLE|DF_AUTOIDX, NULL },
		{ NL80211_STA_INFO_TID_STATS, "tid_stats", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_tid_stats_nla },
		{ NL80211_STA_INFO_BSS_PARAM, "bss_param", DT_NESTED, 0, &nl80211_bss_param_nla },
		{ NL80211_STA_INFO_RX_DURATION, "rx_duration", DT_U64, 0, NULL },
		{ NL80211_STA_INFO_TX_DURATION, "tx_duration", DT_U64, 0, NULL },
		{ NL80211_STA_INFO_ACK_SIGNAL, "ack_signal", DT_S8, 0, NULL },
		{ NL80211_STA_INFO_ACK_SIGNAL_AVG, "ack_signal_avg", DT_S8, 0, NULL },
		{ NL80211_STA_INFO_AIRTIME_LINK_METRIC, "airtime_link_metric", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_AIRTIME_WEIGHT, "airtime_weight", DT_U16, 0, NULL },
		{ NL80211_STA_INFO_CONNECTED_TO_AS, "connected_to_as", DT_BOOL, 0, NULL },
		{ NL80211_STA_INFO_CONNECTED_TO_GATE, "connected_to_gate", DT_BOOL, 0, NULL },
		{ NL80211_STA_INFO_CONNECTED_TIME, "connected_time", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_ASSOC_AT_BOOTTIME, "assoc_at_boottime", DT_U64, 0, NULL },
		{ NL80211_STA_INFO_BEACON_SIGNAL_AVG, "beacon_signal_avg", DT_S8, 0, NULL },
		{ NL80211_STA_INFO_EXPECTED_THROUGHPUT, "expected_throughput", DT_U32, 0, NULL },
		{ NL80211_STA_INFO_SIGNAL_AVG, "signal_avg", DT_S8, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_survey_info_nla = {
	.headsize = 0,
	.nattrs = 8,
	.attrs = {
		{ NL80211_SURVEY_INFO_FREQUENCY, "frequency", DT_U32, 0, NULL },
		{ NL80211_SURVEY_INFO_TIME, "time", DT_U64, 0, NULL },
		{ NL80211_SURVEY_INFO_TIME_TX, "time_tx", DT_U64, 0, NULL },
		{ NL80211_SURVEY_INFO_TIME_RX, "time_rx", DT_U64, 0, NULL },
		{ NL80211_SURVEY_INFO_TIME_BUSY, "busy", DT_U64, 0, NULL },
		{ NL80211_SURVEY_INFO_TIME_EXT_BUSY, "ext_busy", DT_U64, 0, NULL },
		{ NL80211_SURVEY_INFO_TIME_SCAN, "scan", DT_U64, 0, NULL },
		{ NL80211_SURVEY_INFO_NOISE, "noise", DT_S8, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_mpath_info_nla = {
	.headsize = 0,
	.nattrs = 8,
	.attrs = {
		{ NL80211_MPATH_INFO_SN, "sn", DT_U32, 0, NULL },
		{ NL80211_MPATH_INFO_METRIC, "metric", DT_U32, 0, NULL },
		{ NL80211_MPATH_INFO_EXPTIME, "expire", DT_U32, 0, NULL },
		{ NL80211_MPATH_INFO_DISCOVERY_TIMEOUT, "discovery_timeout", DT_U32, 0, NULL },
		{ NL80211_MPATH_INFO_DISCOVERY_RETRIES, "discovery_retries", DT_U8, 0, NULL },
		{ NL80211_MPATH_INFO_FLAGS, "flags", DT_U8, 0, NULL },
		{ NL80211_MPATH_INFO_HOP_COUNT, "hop_count", DT_U8, 0, NULL },
		{ NL80211_MPATH_INFO_PATH_CHANGE, "path_change", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_radio_freq_range_nla = {
	.headsize = 0,
	.nattrs = 2,
	.attrs = {
		{ NL80211_WIPHY_RADIO_FREQ_ATTR_START, "start", DT_U32, 0, NULL },
		{ NL80211_WIPHY_RADIO_FREQ_ATTR_END, "end", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_wiphy_radio_nla = {
	.headsize = 0,
	.nattrs = 4,
	.attrs = {
		{ NL80211_WIPHY_RADIO_ATTR_INDEX, "index", DT_U32, 0, NULL },
		{ NL80211_WIPHY_RADIO_ATTR_FREQ_RANGE, "freq_ranges", DT_NESTED, DF_REPEATED, &nl80211_radio_freq_range_nla },
		{ NL80211_WIPHY_RADIO_ATTR_INTERFACE_COMBINATION, "interface_combinations", DT_NESTED, DF_REPEATED, &nl80211_ifcomb_nla },
		{ NL80211_WIPHY_RADIO_ATTR_ANTENNA_MASK, "antenna_mask", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t nl80211_msg = {
	.headsize = 0,
	.nattrs = 130,
	.attrs = {
		{ NL80211_ATTR_4ADDR, "4addr", DT_U8, 0, NULL },
		{ NL80211_ATTR_AIRTIME_WEIGHT, "airtime_weight", DT_U16, 0, NULL },
		{ NL80211_ATTR_AKM_SUITES, "akm_suites", DT_U32, 0, NULL },
		{ NL80211_ATTR_AUTH_TYPE, "auth_type", DT_U32, 0, NULL },
		{ NL80211_ATTR_BANDS, "bands", DT_U32, 0, NULL },
		{ NL80211_ATTR_BEACON_HEAD, "beacon_head", DT_STRING, DF_BINARY, NULL },
		{ NL80211_ATTR_BEACON_INTERVAL, "beacon_interval", DT_U32, 0, NULL },
		{ NL80211_ATTR_BEACON_TAIL, "beacon_tail", DT_STRING, DF_BINARY, NULL },
		{ NL80211_ATTR_BSS, "bss", DT_NESTED, 0, &nl80211_bss_nla },
		{ NL80211_ATTR_BSS_BASIC_RATES, "bss_basic_rates", DT_U32, DF_ARRAY, NULL },
		{ NL80211_ATTR_CENTER_FREQ1, "center_freq1", DT_U32, 0, NULL },
		{ NL80211_ATTR_CENTER_FREQ2, "center_freq2", DT_U32, 0, NULL },
		{ NL80211_ATTR_CHANNEL_WIDTH, "channel_width", DT_U32, 0, NULL },
		{ NL80211_ATTR_CH_SWITCH_BLOCK_TX, "ch_switch_block_tx", DT_FLAG, 0, NULL },
		{ NL80211_ATTR_CH_SWITCH_COUNT, "ch_switch_count", DT_U32, 0, NULL },
		{ NL80211_ATTR_CIPHER_SUITES, "cipher_suites", DT_U32, DF_ARRAY, NULL },
		{ NL80211_ATTR_CIPHER_SUITES_PAIRWISE, "cipher_suites_pairwise", DT_U32, 0, NULL },
		{ NL80211_ATTR_CIPHER_SUITE_GROUP, "cipher_suite_group", DT_U32, 0, NULL },
		{ NL80211_ATTR_COALESCE_RULE, "coalesce_rule", DT_NESTED, 0, &nl80211_coalesce_rule_nla },
		{ NL80211_ATTR_COOKIE, "cookie", DT_U64, 0, NULL },
		{ NL80211_ATTR_CQM, "cqm", DT_NESTED, 0, &nl80211_cqm_nla },
		{ NL80211_ATTR_DFS_CAC_TIME, "dfs_cac_time", DT_U32, 0, NULL },
		{ NL80211_ATTR_DFS_REGION, "dfs_region", DT_U8, 0, NULL },
		{ NL80211_ATTR_DTIM_PERIOD, "dtim_period", DT_U32, 0, NULL },
		{ NL80211_ATTR_DURATION, "duration", DT_U32, 0, NULL },
		{ NL80211_ATTR_EXT_FEATURES, "extended_features", DT_U8, DF_ARRAY, NULL },
		{ NL80211_ATTR_FEATURE_FLAGS, "feature_flags", DT_U32, 0, NULL },
		{ NL80211_ATTR_FRAME, "frame", DT_STRING, DF_BINARY, NULL },
		{ NL80211_ATTR_FRAME_MATCH, "frame_match", DT_STRING, DF_BINARY, NULL },
		{ NL80211_ATTR_FRAME_TYPE, "frame_type", DT_U16, 0, NULL },
		{ NL80211_ATTR_FREQ_FIXED, "freq_fixed", DT_FLAG, 0, NULL },
		{ NL80211_ATTR_FTM_RESPONDER, "ftm_responder", DT_NESTED, 0, &nl80211_ftm_responder_nla },
		{ NL80211_ATTR_FTM_RESPONDER_STATS, "ftm_responder_stats", DT_NESTED, 0, &nl80211_ftm_responder_stats_nla },
		{ NL80211_ATTR_HIDDEN_SSID, "hidden_ssid", DT_U32, 0, NULL },
		{ NL80211_ATTR_HT_CAPABILITY_MASK, "ht_capability_mask", DT_HT_CAP, 0, NULL },
		{ NL80211_ATTR_IE, "ie", DT_IE, 0, NULL },
		{ NL80211_ATTR_IFINDEX, "dev", DT_NETDEV, 0, NULL },
		{ NL80211_ATTR_IFNAME, "ifname", DT_STRING, 0, NULL },
		{ NL80211_ATTR_IFTYPE, "iftype", DT_U32, 0, NULL },
		{ NL80211_ATTR_INACTIVITY_TIMEOUT, "inactivity_timeout", DT_U16, 0, NULL },
		{ NL80211_ATTR_INTERFACE_COMBINATIONS, "interface_combinations", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_ifcomb_nla },
		{ NL80211_ATTR_KEYS, "keys", DT_NESTED, DF_AUTOIDX, &nl80211_keys_nla },
		{ NL80211_ATTR_KEY_SEQ, "key_seq", DT_STRING, DF_BINARY, NULL },
		{ NL80211_ATTR_KEY_TYPE, "key_type", DT_U32, 0, NULL },
		{ NL80211_ATTR_LOCAL_MESH_POWER_MODE, "local_mesh_power_mode", DT_U32, 0, NULL },
		{ NL80211_ATTR_MAC, "mac", DT_LLADDR, 0, NULL },
		{ NL80211_ATTR_MAC_MASK, "mac_mask", DT_LLADDR, 0, NULL },
		{ NL80211_ATTR_MCAST_RATE, "mcast_rate", DT_U32, 0, NULL },
		{ NL80211_ATTR_MEASUREMENT_DURATION, "measurement_duration", DT_U16, 0, NULL },
		{ NL80211_ATTR_MESH_ID, "mesh_id", DT_STRING, 0, NULL },
		{ NL80211_ATTR_MESH_PARAMS, "mesh_params", DT_NESTED, 0, &nl80211_mesh_params_nla },
		{ NL80211_ATTR_MESH_SETUP, "mesh_setup", DT_NESTED, 0, &nl80211_mesh_setup_nla },
		{ NL80211_ATTR_MGMT_SUBTYPE, "mgmt_subtype", DT_U8, 0, NULL },
		{ NL80211_ATTR_MNTR_FLAGS, "mntr_flags", DT_NESTED, 0, &nl80211_mntr_flags_nla },
		{ NL80211_ATTR_MPATH_NEXT_HOP, "mpath_next_hop", DT_LLADDR, 0, NULL },
		{ NL80211_ATTR_MPATH_INFO, "mpath_info", DT_NESTED, 0, &nl80211_mpath_info_nla },
		{ NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR, "mu_mimo_follow_mac_addr", DT_LLADDR, 0, NULL },
		{ NL80211_ATTR_NAN_FUNC, "nan_func", DT_NESTED, 0, &nl80211_nan_func_nla },
		{ NL80211_ATTR_NAN_MASTER_PREF, "nan_master_pref", DT_U8, 0, NULL },
		{ NL80211_ATTR_NETNS_FD, "netns_fd", DT_U32, 0, NULL },
		{ NL80211_ATTR_NOACK_MAP, "noack_map", DT_U16, 0, NULL },
		{ NL80211_ATTR_NSS, "nss", DT_U8, 0, NULL },
		{ NL80211_ATTR_PEER_MEASUREMENTS, "peer_measurements", DT_NESTED, 0, &nl80211_peer_measurements_nla },
		{ NL80211_ATTR_PID, "pid", DT_U32, 0, NULL },
		{ NL80211_ATTR_PMK, "pmk", DT_STRING, DF_BINARY, NULL },
		{ NL80211_ATTR_PRIVACY, "privacy", DT_FLAG, 0, NULL },
		{ NL80211_ATTR_PROTOCOL_FEATURES, "protocol_features", DT_U32, 0, NULL },
		{ NL80211_ATTR_PS_STATE, "ps_state", DT_U32, 0, NULL },
		{ NL80211_ATTR_RADAR_EVENT, "radar_event", DT_U32, 0, NULL },
		{ NL80211_ATTR_REASON_CODE, "reason_code", DT_U16, 0, NULL },
		{ NL80211_ATTR_REG_ALPHA2, "reg_alpha2", DT_STRING, 0, NULL },
		{ NL80211_ATTR_REG_INITIATOR, "reg_initiator", DT_U32, 0, NULL },
		{ NL80211_ATTR_REG_RULES, "reg_rules", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_reg_rules_nla },
		{ NL80211_ATTR_REG_TYPE, "reg_type", DT_U8, 0, NULL },
		{ NL80211_ATTR_RX_FRAME_TYPES, "rx_frame_types", DT_NESTED, 0, &nl80211_frame_types_nla },
		{ NL80211_ATTR_RX_SIGNAL_DBM, "rx_signal_dbm", DT_U32, 0, NULL },
		{ NL80211_ATTR_SCAN_FLAGS, "scan_flags", DT_U32, 0, NULL },
		{ NL80211_ATTR_SCAN_FREQUENCIES, "scan_frequencies", DT_U32, DF_MULTIPLE|DF_AUTOIDX, NULL },
		{ NL80211_ATTR_SCAN_SSIDS, "scan_ssids", DT_STRING, DF_MULTIPLE|DF_AUTOIDX, NULL },
		{ NL80211_ATTR_SCHED_SCAN_DELAY, "sched_scan_delay", DT_U32, 0, NULL },
		{ NL80211_ATTR_SCHED_SCAN_INTERVAL, "sched_scan_interval", DT_U32, 0, NULL },
		{ NL80211_ATTR_SCHED_SCAN_MATCH, "sched_scan_match", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_sched_scan_match_nla },
		{ NL80211_ATTR_SCHED_SCAN_PLANS, "sched_scan_plans", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX|DF_OFFSET1, &nl80211_sched_scan_plan_nla },
		{ NL80211_ATTR_SMPS_MODE, "smps_mode", DT_U8, 0, NULL },
		{ NL80211_ATTR_SPLIT_WIPHY_DUMP, "split_wiphy_dump", DT_FLAG, 0, NULL },
		{ NL80211_ATTR_SSID, "ssid", DT_STRING, DF_BINARY, NULL },
		{ NL80211_ATTR_STATUS_CODE, "status_code", DT_U16, 0, NULL },
		{ NL80211_ATTR_STA_INFO, "sta_info", DT_NESTED, 0, &nl80211_sta_info_nla },
		{ NL80211_ATTR_STA_PLINK_ACTION, "sta_plink_action", DT_U8, 0, NULL },
		{ NL80211_ATTR_STA_TX_POWER, "sta_tx_power", DT_U16, 0, NULL },
		{ NL80211_ATTR_STA_TX_POWER_SETTING, "sta_tx_power_setting", DT_U8, 0, NULL },
		{ NL80211_ATTR_STA_VLAN, "sta_vlan", DT_U32, 0, NULL },
		{ NL80211_ATTR_SUPPORTED_COMMANDS, "supported_commands", DT_U32, DF_NO_SET|DF_MULTIPLE|DF_AUTOIDX, NULL },
		{ NL80211_ATTR_TESTDATA, "testdata", DT_NESTED, 0, &nl80211_testdata_nla },
		{ NL80211_ATTR_TID_CONFIG, "tid_config", DT_NESTED, DF_MULTIPLE, &nl80211_tid_config_nla },
		{ NL80211_ATTR_TIMEOUT, "timeout", DT_U32, 0, NULL },
		{ NL80211_ATTR_TXQ_LIMIT, "txq_limit", DT_U32, 0, NULL },
		{ NL80211_ATTR_TXQ_MEMORY_LIMIT, "txq_memory_limit", DT_U32, 0, NULL },
		{ NL80211_ATTR_TXQ_QUANTUM, "txq_quantum", DT_U32, 0, NULL },
		{ NL80211_ATTR_TX_FRAME_TYPES, "tx_frame_types", DT_NESTED, 0, &nl80211_frame_types_nla },
		{ NL80211_ATTR_USE_MFP, "use_mfp", DT_U32, 0, NULL },
		{ NL80211_ATTR_VENDOR_DATA, "vendor_data", DT_STRING, DF_BINARY, NULL },
		{ NL80211_ATTR_VENDOR_ID, "vendor_id", DT_U32, 0, NULL },
		{ NL80211_ATTR_VENDOR_SUBCMD, "vendor_subcmd", DT_U32, 0, NULL },
		{ NL80211_ATTR_WDEV, "wdev", DT_U64, 0, NULL },
		{ NL80211_ATTR_WIPHY, "wiphy", DT_U32, 0, NULL },
		{ NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX, "wiphy_antenna_avail_rx", DT_U32, 0, NULL },
		{ NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX, "wiphy_antenna_avail_tx", DT_U32, 0, NULL },
		{ NL80211_ATTR_WIPHY_ANTENNA_RX, "wiphy_antenna_rx", DT_U32, 0, NULL },
		{ NL80211_ATTR_WIPHY_ANTENNA_TX, "wiphy_antenna_tx", DT_U32, 0, NULL },
		{ NL80211_ATTR_WIPHY_BANDS, "wiphy_bands", DT_NESTED, DF_NO_SET|DF_MULTIPLE|DF_TYPEIDX, &nl80211_wiphy_bands_nla },
		{ NL80211_ATTR_WIPHY_CHANNEL_TYPE, "wiphy_channel_type", DT_U32, 0, NULL },
		{ NL80211_ATTR_WIPHY_COVERAGE_CLASS, "wiphy_coverage_class", DT_U8, 0, NULL },
		{ NL80211_ATTR_WIPHY_DYN_ACK, "wiphy_dyn_ack", DT_FLAG, 0, NULL },
		{ NL80211_ATTR_WIPHY_FRAG_THRESHOLD, "wiphy_frag_threshold", DT_S32, 0, NULL },
		{ NL80211_ATTR_WIPHY_FREQ, "wiphy_freq", DT_U32, 0, NULL },
		{ NL80211_ATTR_WIPHY_NAME, "wiphy_name", DT_STRING, 0, NULL },
		{ NL80211_ATTR_WIPHY_RETRY_LONG, "wiphy_retry_long", DT_U8, 0, NULL },
		{ NL80211_ATTR_WIPHY_RETRY_SHORT, "wiphy_retry_short", DT_U8, 0, NULL },
		{ NL80211_ATTR_WIPHY_RTS_THRESHOLD, "wiphy_rts_threshold", DT_S32, 0, NULL },
		{ NL80211_ATTR_WIPHY_TX_POWER_LEVEL, "wiphy_tx_power_level", DT_U32, 0, NULL },
		{ NL80211_ATTR_WIPHY_TX_POWER_SETTING, "wiphy_tx_power_setting", DT_U32, 0, NULL },
		{ NL80211_ATTR_WOWLAN_TRIGGERS, "wowlan_triggers", DT_NESTED, 0, &nl80211_wowlan_triggers_nla },
		{ NL80211_ATTR_WPA_VERSIONS, "wpa_versions", DT_U32, 0, NULL },
		{ NL80211_ATTR_SUPPORTED_IFTYPES, "supported_iftypes", DT_NESTED, 0, &nl80211_ifcomb_limit_types_nla },
		{ NL80211_ATTR_SOFTWARE_IFTYPES, "software_iftypes", DT_NESTED, 0, &nl80211_ifcomb_limit_types_nla },
		{ NL80211_ATTR_MAX_AP_ASSOC_STA, "max_ap_assoc", DT_U16, 0, NULL },
		{ NL80211_ATTR_SURVEY_INFO, "survey_info", DT_NESTED, 0, &nl80211_survey_info_nla },
		{ NL80211_ATTR_WIPHY_RADIOS, "radios", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_wiphy_radio_nla },
		{ NL80211_ATTR_VIF_RADIO_MASK, "vif_radio_mask", DT_U32, 0, NULL },
	}
};

static const uc_nl_nested_spec_t hwsim_tx_info_struct = {
	.headsize = sizeof(struct hwsim_tx_rate),
	.nattrs = 2,
	.attrs = {
		{ NLA_UNSPEC, "idx", DT_S8, 0, MEMBER(hwsim_tx_rate, idx) },
		{ NLA_UNSPEC, "count", DT_U8, 0, MEMBER(hwsim_tx_rate, count) },
	}
};

static const uc_nl_nested_spec_t hwsim_tx_info_flags_struct = {
	.headsize = sizeof(struct hwsim_tx_rate_flag),
	.nattrs = 2,
	.attrs = {
		{ NLA_UNSPEC, "idx", DT_S8, 0, MEMBER(hwsim_tx_rate_flag, idx) },
		{ NLA_UNSPEC, "flags", DT_U16, 0, MEMBER(hwsim_tx_rate_flag, flags) },
	}
};

static const uc_nl_nested_spec_t hwsim_pmsr_support_nla = {
	.headsize = 0,
	.nattrs = 5,
	.attrs = {
		{ NL80211_PMSR_ATTR_MAX_PEERS, "max_peers", DT_U32, 0, NULL },
		{ NL80211_PMSR_ATTR_REPORT_AP_TSF, "report_ap_tsf", DT_FLAG, 0, NULL },
		{ NL80211_PMSR_ATTR_RANDOMIZE_MAC_ADDR, "randomize_mac_addr", DT_FLAG, 0, NULL },
		{ NL80211_PMSR_ATTR_TYPE_CAPA, "type_capa", DT_U32, 0, NULL },
		{ NL80211_PMSR_ATTR_PEERS, "peers", DT_NESTED, DF_MULTIPLE|DF_AUTOIDX, &nl80211_peer_measurements_peers_nla },
	}
};

static const uc_nl_nested_spec_t hwsim_pmsr_request_nla = {
	.headsize = 0,
	.nattrs = 1,
	.attrs = {
		{ NL80211_ATTR_PEER_MEASUREMENTS, "peer_measurements", DT_NESTED, 0, &nl80211_peer_measurements_nla },
	}
};

static const uc_nl_nested_spec_t hwsim_msg = {
	.headsize = 0,
	.nattrs = 27,
	.attrs = {
		{ HWSIM_ATTR_ADDR_RECEIVER, "addr_receiver", DT_LLADDR, 0, NULL },
		{ HWSIM_ATTR_ADDR_TRANSMITTER, "addr_transmitter", DT_LLADDR, 0, NULL },
		{ HWSIM_ATTR_FRAME, "frame", DT_STRING, DF_BINARY, NULL },
		{ HWSIM_ATTR_FLAGS, "flags", DT_U32, 0, NULL },
		{ HWSIM_ATTR_RX_RATE, "rx_rate", DT_U32, 0, NULL },
		{ HWSIM_ATTR_SIGNAL, "signal", DT_U32, 0, NULL },
		{ HWSIM_ATTR_TX_INFO, "tx_info", DT_NESTED, DF_ARRAY, &hwsim_tx_info_struct },
		{ HWSIM_ATTR_COOKIE, "cookie", DT_U64, 0, NULL },
		{ HWSIM_ATTR_CHANNELS, "channels", DT_U32, 0, NULL },
		{ HWSIM_ATTR_RADIO_ID, "radio_id", DT_U32, 0, NULL },
		{ HWSIM_ATTR_REG_HINT_ALPHA2, "reg_hint_alpha2", DT_STRING, DF_BINARY, NULL },
		{ HWSIM_ATTR_REG_CUSTOM_REG, "reg_custom_reg", DT_U32, 0, NULL },
		{ HWSIM_ATTR_REG_STRICT_REG, "reg_strict_reg", DT_FLAG, 0, NULL },
		{ HWSIM_ATTR_SUPPORT_P2P_DEVICE, "support_p2p_device", DT_FLAG, 0, NULL },
		{ HWSIM_ATTR_USE_CHANCTX, "use_chanctx", DT_FLAG, 0, NULL },
		{ HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE, "destroy_radio_on_close", DT_FLAG, 0, NULL },
		{ HWSIM_ATTR_RADIO_NAME, "radio_name", DT_STRING, DF_BINARY, NULL },
		{ HWSIM_ATTR_NO_VIF, "no_vif", DT_FLAG, 0, NULL },
		{ HWSIM_ATTR_FREQ, "freq", DT_U32, 0, NULL },
		{ HWSIM_ATTR_TX_INFO_FLAGS, "tx_info_flags", DT_NESTED, DF_ARRAY, &hwsim_tx_info_flags_struct },
		{ HWSIM_ATTR_PERM_ADDR, "perm_addr", DT_LLADDR, 0, NULL },
		{ HWSIM_ATTR_IFTYPE_SUPPORT, "iftype_support", DT_U32, 0, NULL },
		{ HWSIM_ATTR_CIPHER_SUPPORT, "cipher_support", DT_U32, DF_ARRAY, NULL },
		{ HWSIM_ATTR_MLO_SUPPORT, "mlo_support", DT_FLAG, 0, NULL },
		{ HWSIM_ATTR_PMSR_SUPPORT, "pmsr_support", DT_NESTED, 0, &hwsim_pmsr_support_nla },
		{ HWSIM_ATTR_PMSR_REQUEST, "pmsr_request", DT_NESTED, 0, &hwsim_pmsr_request_nla },
		{ HWSIM_ATTR_PMSR_RESULT, "pmsr_result", DT_NESTED, 0, &hwsim_pmsr_support_nla },
	}
};


static bool
nla_check_len(struct nlattr *nla, size_t sz)
{
	return (nla && nla_len(nla) >= (ssize_t)sz);
}

static bool
nla_parse_error(const uc_nl_attr_spec_t *spec, uc_vm_t *vm, uc_value_t *v, const char *msg)
{
	char *s;

	s = ucv_to_string(vm, v);

	set_error(vm, NLE_INVAL, "%s `%s` has invalid value `%s`: %s",
		spec->attr ? "attribute" : "field",
		spec->key,
		s,
		msg);

	free(s);

	return false;
}

static void
uc_nl_put_struct_member(char *base, const void *offset, size_t datalen, void *data)
{
	memcpy(base + (uintptr_t)offset, data, datalen);
}

static void
uc_nl_put_struct_member_u8(char *base, const void *offset, uint8_t u8)
{
	base[(uintptr_t)offset] = u8;
}

static void
uc_nl_put_struct_member_u32(char *base, const void *offset, uint32_t u32)
{
	uc_nl_put_struct_member(base, offset, sizeof(u32), &u32);
}

static void *
uc_nl_get_struct_member(char *base, const void *offset, size_t datalen, void *data)
{
	memcpy(data, base + (uintptr_t)offset, datalen);

	return data;
}

static uint8_t
uc_nl_get_struct_member_u8(char *base, const void *offset)
{
	return (uint8_t)base[(uintptr_t)offset];
}

static uint32_t
uc_nl_get_struct_member_u32(char *base, const void *offset)
{
	uint32_t u32;

	uc_nl_get_struct_member(base, offset, sizeof(u32), &u32);

	return u32;
}

static bool
uc_nl_parse_attr(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, char *base, uc_vm_t *vm, uc_value_t *val, size_t idx);

static uc_value_t *
uc_nl_convert_attr(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, char *base, struct nlattr *attr, struct nlattr *attr2, uc_vm_t *vm);

static bool
uc_nl_convert_attrs(struct nl_msg *msg, void *buf, size_t buflen, size_t headsize, const uc_nl_attr_spec_t *attrs, size_t nattrs, uc_vm_t *vm, uc_value_t *obj)
{
	struct nlattr **tb, *nla, *nla2, *nla_nest;
	size_t i, type, maxattr = 0;
	uc_value_t *v, *arr;
	int rem;

	for (i = 0; i < nattrs; i++)
		if (attrs[i].attr > maxattr)
			maxattr = attrs[i].attr;

	tb = calloc(maxattr + 1, sizeof(struct nlattr *));

	if (!tb)
		return false;

	nla_for_each_attr(nla, buf + headsize, buflen - headsize, rem) {
		type = nla_type(nla);

		if (type <= maxattr && !tb[type])
			tb[type] = nla;
	}

	for (i = 0; i < nattrs; i++) {
		if (attrs[i].attr != 0 && !tb[attrs[i].attr])
			continue;

		if (attrs[i].flags & DF_REPEATED) {
			arr = ucv_array_new(vm);

			nla = tb[attrs[i].attr];
			rem = buflen - ((void *)nla - buf);
			for (; nla_ok(nla, rem); nla = nla_next(nla, &rem)) {
				if (nla_type(nla) != (int)attrs[i].attr)
					break;
				v = uc_nl_convert_attr(&attrs[i], msg, (char *)buf, nla, NULL, vm);
				if (!v)
					continue;

				ucv_array_push(arr, v);
			}
			if (!ucv_array_length(arr)) {
				ucv_put(arr);
				continue;
			}

			v = arr;
		}
		else if (attrs[i].flags & DF_MULTIPLE) {
			arr = ucv_array_new(vm);
			nla_nest = tb[attrs[i].attr];

			nla_for_each_attr(nla, nla_data(nla_nest), nla_len(nla_nest), rem) {
				if (!(attrs[i].flags & (DF_AUTOIDX|DF_TYPEIDX)) &&
				    attrs[i].auxdata && nla_type(nla) != (intptr_t)attrs[i].auxdata)
					continue;

				v = uc_nl_convert_attr(&attrs[i], msg, (char *)buf, nla, NULL, vm);

				if (!v)
					continue;

				if (attrs[i].flags & DF_TYPEIDX)
					ucv_array_set(arr, nla_type(nla) - !!(attrs[i].flags & DF_OFFSET1), v);
				else
					ucv_array_push(arr, v);
			}

			if (!ucv_array_length(arr)) {
				ucv_put(arr);

				continue;
			}

			v = arr;
		}
		else {
			if (attrs[i].flags & DF_RELATED)
				nla2 = tb[(uintptr_t)attrs[i].auxdata];
			else
				nla2 = NULL;

			v = uc_nl_convert_attr(&attrs[i], msg, (char *)buf, tb[attrs[i].attr], nla2, vm);

			if (!v)
				continue;
		}

		ucv_object_add(obj, attrs[i].key, v);
	}

	free(tb);

	return true;
}

static bool
uc_nl_parse_attrs(struct nl_msg *msg, char *base, const uc_nl_attr_spec_t *attrs, size_t nattrs, uc_vm_t *vm, uc_value_t *obj)
{
	struct nlattr *nla_nest = NULL;
	uc_value_t *v, *item;
	size_t i, j, idx;
	bool exists;

	for (i = 0; i < nattrs; i++) {
		if (attrs[i].attr == NL80211_ATTR_NOT_IMPLEMENTED)
			continue;

		v = ucv_object_get(obj, attrs[i].key, &exists);

		if (!exists)
			continue;

		if (attrs[i].flags & DF_MULTIPLE) {
			nla_nest = nla_nest_start(msg, attrs[i].attr);

			if (ucv_type(v) == UC_ARRAY) {
				for (j = 0; j < ucv_array_length(v); j++) {
					item = ucv_array_get(v, j);

					if (!item && (attrs[i].flags & DF_TYPEIDX))
						continue;

					if (!attrs[i].auxdata || (attrs[i].flags & (DF_AUTOIDX|DF_TYPEIDX)))
						idx = j + !!(attrs[i].flags & DF_OFFSET1);
					else
						idx = (uintptr_t)attrs[i].auxdata;

					if (!uc_nl_parse_attr(&attrs[i], msg, base, vm, item, idx))
						return false;
				}
			}
			else {
				if (!attrs[i].auxdata || (attrs[i].flags & (DF_AUTOIDX|DF_TYPEIDX)))
					idx = !!(attrs[i].flags & DF_OFFSET1);
				else
					idx = (uintptr_t)attrs[i].auxdata;

				if (!uc_nl_parse_attr(&attrs[i], msg, base, vm, v, idx))
					return false;
			}

			nla_nest_end(msg, nla_nest);
		}
		else if (!uc_nl_parse_attr(&attrs[i], msg, base, vm, v, 0)) {
			return false;
		}
	}

	return true;
}

static bool
uc_nl_parse_rta_nested(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, char *base, uc_vm_t *vm, uc_value_t *val)
{
	const uc_nl_nested_spec_t *nest = spec->auxdata;
	struct nlattr *nested_nla;

	if (!nest)
		return false;

	nested_nla = nla_reserve(msg, spec->attr, nest->headsize);

	if (!uc_nl_parse_attrs(msg, nla_data(nested_nla), nest->attrs, nest->nattrs, vm, val))
		return false;

	nla_nest_end(msg, nested_nla);

	return true;
}

static uc_value_t *
uc_nl_convert_rta_nested(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, struct nlattr *attr, uc_vm_t *vm)
{
	const uc_nl_nested_spec_t *nest = spec->auxdata;
	uc_value_t *nested_obj;
	bool rv;

	if (!nest)
		return NULL;

	if (!nla_check_len(attr, nest->headsize))
		return NULL;

	nested_obj = ucv_object_new(vm);

	rv = uc_nl_convert_attrs(msg,
		nla_data(attr), nla_len(attr), nest->headsize,
		nest->attrs, nest->nattrs,
		vm, nested_obj);

	if (!rv) {
		ucv_put(nested_obj);

		return NULL;
	}

	return nested_obj;
}

static uc_value_t *
uc_nl_convert_rta_ht_mcs(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, struct nlattr *attr, uc_vm_t *vm)
{
	uc_value_t *mcs_obj, *mcs_idx;
	uint16_t max_rate = 0;
	uint8_t *mcs;
	size_t i;

	if (!nla_check_len(attr, 16))
		return NULL;

	mcs = nla_data(attr);
	mcs_obj = ucv_object_new(vm);

	max_rate = (mcs[10] | ((mcs[11] & 0x3) << 8));

	if (max_rate)
		ucv_object_add(mcs_obj, "rx_highest_data_rate", ucv_uint64_new(max_rate));

	mcs_idx = ucv_array_new(vm);

	for (i = 0; i <= 76; i++)
		if (mcs[i / 8] & (1 << (i % 8)))
			ucv_array_push(mcs_idx, ucv_uint64_new(i));

	ucv_object_add(mcs_obj, "rx_mcs_indexes", mcs_idx);

	ucv_object_add(mcs_obj, "tx_mcs_set_defined", ucv_boolean_new(mcs[12] & (1 << 0)));
	ucv_object_add(mcs_obj, "tx_rx_mcs_set_equal", ucv_boolean_new(!(mcs[12] & (1 << 1))));
	ucv_object_add(mcs_obj, "tx_max_spatial_streams", ucv_uint64_new(((mcs[12] >> 2) & 3) + 1));
	ucv_object_add(mcs_obj, "tx_unequal_modulation", ucv_boolean_new(mcs[12] & (1 << 4)));

	return mcs_obj;
}

static uc_value_t *
uc_nl_convert_rta_ht_cap(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, struct nlattr *attr, uc_vm_t *vm)
{
	uc_value_t *cap_obj, *mcs_obj, *rx_mask;
	struct ieee80211_ht_cap *cap;
	size_t i;

	if (!nla_check_len(attr, sizeof(*cap)))
		return NULL;

	cap = nla_data(attr);
	cap_obj = ucv_object_new(vm);

	ucv_object_add(cap_obj, "cap_info", ucv_uint64_new(le16toh(cap->cap_info)));
	ucv_object_add(cap_obj, "ampdu_params_info", ucv_uint64_new(cap->ampdu_params_info));
	ucv_object_add(cap_obj, "extended_ht_cap_info", ucv_uint64_new(le16toh(cap->extended_ht_cap_info)));
	ucv_object_add(cap_obj, "tx_BF_cap_info", ucv_uint64_new(le32toh(cap->tx_BF_cap_info)));
	ucv_object_add(cap_obj, "antenna_selection_info", ucv_uint64_new(cap->antenna_selection_info));

	mcs_obj = ucv_object_new(vm);
	rx_mask = ucv_array_new_length(vm, sizeof(cap->mcs.rx_mask));

	for (i = 0; i < sizeof(cap->mcs.rx_mask); i++)
		ucv_array_push(rx_mask, ucv_uint64_new(cap->mcs.rx_mask[i]));

	ucv_object_add(mcs_obj, "rx_mask", rx_mask);
	ucv_object_add(mcs_obj, "rx_highest", ucv_uint64_new(le16toh(cap->mcs.rx_highest)));
	ucv_object_add(mcs_obj, "tx_params", ucv_uint64_new(cap->mcs.tx_params));

	ucv_object_add(cap_obj, "mcs", mcs_obj);

	return cap_obj;
}

static uc_value_t *
uc_nl_convert_rta_vht_mcs(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, struct nlattr *attr, uc_vm_t *vm)
{
	uc_value_t *mcs_obj, *mcs_set, *mcs_entry, *mcs_idx;
	size_t i, j, max_idx;
	uint16_t u16;
	uint8_t *mcs;

	if (!nla_check_len(attr, 8))
		return NULL;

	mcs = nla_data(attr);
	mcs_obj = ucv_object_new(vm);

	u16 = mcs[0] | (mcs[1] << 8);
	mcs_set = ucv_array_new(vm);

	for (i = 1; i <= 8; i++) {
		switch ((u16 >> ((i - 1) * 2)) & 3) {
		case 0: max_idx = 7; break;
		case 1: max_idx = 8; break;
		case 2: max_idx = 9; break;
		default: continue;
		}

		mcs_idx = ucv_array_new_length(vm, max_idx + 1);

		for (j = 0; j <= max_idx; j++)
			ucv_array_push(mcs_idx, ucv_uint64_new(j));

		mcs_entry = ucv_object_new(vm);

		ucv_object_add(mcs_entry, "streams", ucv_uint64_new(i));
		ucv_object_add(mcs_entry, "mcs_indexes", mcs_idx);

		ucv_array_push(mcs_set, mcs_entry);
	}

	ucv_object_add(mcs_obj, "rx_mcs_set", mcs_set);
	ucv_object_add(mcs_obj, "rx_highest_data_rate", ucv_uint64_new((mcs[2] | (mcs[3] << 8)) & 0x1fff));

	u16 = mcs[4] | (mcs[5] << 8);
	mcs_set = ucv_array_new(vm);

	for (i = 1; i <= 8; i++) {
		switch ((u16 >> ((i - 1) * 2)) & 3) {
		case 0: max_idx = 7; break;
		case 1: max_idx = 8; break;
		case 2: max_idx = 9; break;
		default: continue;
		}

		mcs_idx = ucv_array_new_length(vm, max_idx + 1);

		for (j = 0; j <= max_idx; j++)
			ucv_array_push(mcs_idx, ucv_uint64_new(j));

		mcs_entry = ucv_object_new(vm);

		ucv_object_add(mcs_entry, "streams", ucv_uint64_new(i));
		ucv_object_add(mcs_entry, "mcs_indexes", mcs_idx);

		ucv_array_push(mcs_set, mcs_entry);
	}

	ucv_object_add(mcs_obj, "tx_mcs_set", mcs_set);
	ucv_object_add(mcs_obj, "tx_highest_data_rate", ucv_uint64_new((mcs[6] | (mcs[7] << 8)) & 0x1fff));

	return mcs_obj;
}

static uc_value_t *
uc_nl_convert_rta_he_mcs(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, struct nlattr *attr, struct nlattr *phy_attr, uc_vm_t *vm)
{
	uint8_t bw_support_mask[] = { (1 << 1) | (1 << 2), (1 << 3), (1 << 4) };
	uc_value_t *mcs_set, *mcs_bw, *mcs_dir, *mcs_entry, *mcs_idx;
	uint16_t bw[] = { 80, 160, 8080 }, mcs[6];
	uint16_t u16, phy_cap_0 = 0;
	size_t i, j, k, l, max_idx;

	if (!nla_check_len(attr, sizeof(mcs)))
		return NULL;

	if (nla_check_len(phy_attr, sizeof(phy_cap_0)))
		phy_cap_0 = nla_get_u16(phy_attr);

	memcpy(mcs, nla_data(attr), sizeof(mcs));

	mcs_set = ucv_array_new_length(vm, 3);

	for (i = 0; i < ARRAY_SIZE(bw); i++) {
		if (!(phy_cap_0 & (bw_support_mask[i] << 8)))
			continue;

		mcs_bw = ucv_object_new(vm);

		for (j = 0; j < 2; j++) {
			mcs_dir = ucv_array_new_length(vm, 8);

			for (k = 0; k < 8; k++) {
				u16 = mcs[(i * 2) + j];
				u16 >>= k * 2;
				u16 &= 0x3;

				switch (u16) {
				case 0: max_idx = 7; break;
				case 1: max_idx = 9; break;
				case 2: max_idx = 11; break;
				case 3: continue;
				}

				mcs_idx = ucv_array_new_length(vm, max_idx + 1);

				for (l = 0; l <= max_idx; l++)
					ucv_array_push(mcs_idx, ucv_uint64_new(l));

				mcs_entry = ucv_object_new(vm);

				ucv_object_add(mcs_entry, "streams", ucv_uint64_new(k + 1));
				ucv_object_add(mcs_entry, "mcs_indexes", mcs_idx);

				ucv_array_push(mcs_dir, mcs_entry);
			}

			if (ucv_array_length(mcs_dir))
				ucv_object_add(mcs_bw, j ? "tx_mcs_set" : "rx_mcs_set", mcs_dir);
			else
				ucv_put(mcs_dir);
		}

		if (ucv_object_length(mcs_bw)) {
			ucv_object_add(mcs_bw, "bandwidth", ucv_uint64_new(bw[i]));
			ucv_array_push(mcs_set, mcs_bw);
		}
		else {
			ucv_put(mcs_bw);
		}
	}

	return mcs_set;
}

static uc_value_t *
uc_nl_convert_rta_ie(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, struct nlattr *attr, uc_vm_t *vm)
{
	uc_value_t *ie_arr, *ie_obj;
	uint8_t *ie;
	size_t len;

	len = nla_len(attr);
	ie = nla_data(attr);

	if (len < 2)
		return NULL;

	ie_arr = ucv_array_new(vm);

	while (len >= 2 && len - 2 >= ie[1]) {
		ie_obj = ucv_object_new(vm);

		ucv_object_add(ie_obj, "type", ucv_uint64_new(ie[0]));
		ucv_object_add(ie_obj, "data", ucv_string_new_length((char *)&ie[2], ie[1]));

		ucv_array_push(ie_arr, ie_obj);

		len -= ie[1] + 2;
		ie += ie[1] + 2;
	}

	return ie_arr;
}


static bool
uc_nl_parse_numval(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, char *base, uc_vm_t *vm, uc_value_t *val, void *dst)
{
	uint64_t u64;
	uint32_t u32;
	uint16_t u16;
	uint8_t u8;

	switch (spec->type) {
	case DT_U8:
		if (!uc_nl_parse_u32(val, &u32) || u32 > 255)
			return nla_parse_error(spec, vm, val, "not an integer or out of range 0-255");

		u8 = (uint8_t)u32;

		memcpy(dst, &u8, sizeof(u8));
		break;

	case DT_U16:
		if (!uc_nl_parse_u32(val, &u32) || u32 > 65535)
			return nla_parse_error(spec, vm, val, "not an integer or out of range 0-65535");

		u16 = (uint16_t)u32;

		memcpy(dst, &u16, sizeof(u16));
		break;

	case DT_S32:
	case DT_U32:
		if (spec->type == DT_S32 && !uc_nl_parse_s32(val, &u32))
			return nla_parse_error(spec, vm, val, "not an integer or out of range -2147483648-2147483647");
		else if (spec->type == DT_U32 && !uc_nl_parse_u32(val, &u32))
			return nla_parse_error(spec, vm, val, "not an integer or out of range 0-4294967295");

		memcpy(dst, &u32, sizeof(u32));
		break;

	case DT_U64:
		if (!uc_nl_parse_u64(val, &u64))
			return nla_parse_error(spec, vm, val, "not an integer or negative");

		memcpy(dst, &u64, sizeof(u64));
		break;

	default:
		return false;
	}

	return true;
}

static const uint8_t dt_sizes[] = {
	[DT_U8] = sizeof(uint8_t),
	[DT_S8] = sizeof(int8_t),
	[DT_U16] = sizeof(uint16_t),
	[DT_U32] = sizeof(uint32_t),
	[DT_S32] = sizeof(int32_t),
	[DT_U64] = sizeof(uint64_t),
};

static bool
uc_nl_parse_attr(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, char *base, uc_vm_t *vm, uc_value_t *val, size_t idx)
{
	char buf[sizeof(uint64_t)];
	struct in_addr in = { 0 };
	struct ether_addr *ea;
	struct nlattr *nla;
	uc_value_t *item;
	size_t attr, i;
	uint32_t u32;
	char *s;

	if (spec->flags & DF_MULTIPLE)
		attr = idx;
	else
		attr = spec->attr;

	switch (spec->type) {
	case DT_U8:
	case DT_U16:
	case DT_U32:
	case DT_S32:
	case DT_U64:
		if (spec->flags & DF_ARRAY) {
			assert(spec->attr != 0);

			if (ucv_type(val) != UC_ARRAY)
				return nla_parse_error(spec, vm, val, "not an array");

			nla = nla_reserve(msg, spec->attr, ucv_array_length(val) * dt_sizes[spec->type]);
			s = nla_data(nla);

			for (i = 0; i < ucv_array_length(val); i++) {
				item = ucv_array_get(val, i);

				if (!uc_nl_parse_numval(spec, msg, base, vm, item, buf))
					return false;

				memcpy(s, buf, dt_sizes[spec->type]);

				s += dt_sizes[spec->type];
			}
		}
		else {
			if (!uc_nl_parse_numval(spec, msg, base, vm, val, buf))
				return false;

			if (spec->attr == 0)
				uc_nl_put_struct_member(base, spec->auxdata, dt_sizes[spec->type], buf);
			else
				nla_put(msg, attr, dt_sizes[spec->type], buf);
		}

		break;

	case DT_BOOL:
		u32 = (uint32_t)ucv_is_truish(val);

		if (spec->attr == 0)
			uc_nl_put_struct_member_u8(base, spec->auxdata, u32);
		else
			nla_put_u8(msg, attr, u32);

		break;

	case DT_FLAG:
		u32 = (uint32_t)ucv_is_truish(val);

		if (spec->attr == 0)
			uc_nl_put_struct_member_u8(base, spec->auxdata, u32);
		else if (u32 == 1)
			nla_put_flag(msg, attr);

		break;

	case DT_STRING:
		assert(spec->attr != 0);

		s = ucv_to_string(vm, val);

		if (!s)
			return nla_parse_error(spec, vm, val, "out of memory");

		nla_put_string(msg, attr, s);
		free(s);

		break;

	case DT_NETDEV:
		if (ucv_type(val) == UC_INTEGER) {
			if (ucv_int64_get(val) < 0 ||
			    ucv_int64_get(val) > UINT32_MAX)
				return nla_parse_error(spec, vm, val, "interface index out of range 0-4294967295");

			u32 = (uint32_t)ucv_int64_get(val);
		}
		else {
			s = ucv_to_string(vm, val);

			if (!s)
				return nla_parse_error(spec, vm, val, "out of memory");

			u32 = if_nametoindex(s);

			free(s);
		}

		if (spec->attr == 0)
			uc_nl_put_struct_member_u32(base, spec->auxdata, u32);
		else
			nla_put_u32(msg, attr, u32);

		break;

	case DT_LLADDR:
		assert(spec->attr != 0);

		s = ucv_to_string(vm, val);

		if (!s)
			return nla_parse_error(spec, vm, val, "out of memory");

		ea = ether_aton(s);

		free(s);

		if (!ea)
			return nla_parse_error(spec, vm, val, "invalid MAC address");

		nla_put(msg, attr, sizeof(*ea), ea);

		break;

	case DT_INADDR:
		assert(spec->attr != 0);

		if (!uc_nl_parse_ipaddr(vm, val, &in))
			return nla_parse_error(spec, vm, val, "invalid IP address");

		nla_put(msg, attr, sizeof(in), &in);

		break;

	case DT_NESTED:
		if (spec->flags & DF_ARRAY) {
			const uc_nl_nested_spec_t *nested = spec->auxdata;

			assert(nested != NULL);
			assert(nested->headsize > 0);

			if (ucv_type(val) != UC_ARRAY)
				return nla_parse_error(spec, vm, val, "not an array");

			nla = nla_reserve(msg, spec->attr, ucv_array_length(val) * nested->headsize);
			s = nla_data(nla);

			for (i = 0; i < ucv_array_length(val); i++) {
				item = ucv_array_get(val, i);

				if (!uc_nl_parse_attrs(msg, s, nested->attrs, nested->nattrs, vm, item))
					return false;

				s += nested->headsize;
			}

			return true;
		}

		if (!uc_nl_parse_rta_nested(spec, msg, base, vm, val))
			return false;

		break;

	default:
		assert(0);
	}

	return true;
}

static uc_value_t *
uc_nl_convert_numval(const uc_nl_attr_spec_t *spec, char *base)
{
	union { uint8_t *u8; uint16_t *u16; uint32_t *u32; uint64_t *u64; char *base; } t = { .base = base };

	switch (spec->type) {
	case DT_U8:
		return ucv_uint64_new(t.u8[0]);

	case DT_S8:
		return ucv_int64_new((int8_t)t.u8[0]);

	case DT_U16:
		return ucv_uint64_new(t.u16[0]);

	case DT_U32:
		return ucv_uint64_new(t.u32[0]);

	case DT_S32:
		return ucv_int64_new((int32_t)t.u32[0]);

	case DT_U64:
		return ucv_uint64_new(t.u64[0]);

	default:
		return NULL;
	}
}

static uc_value_t *
uc_nl_convert_attr(const uc_nl_attr_spec_t *spec, struct nl_msg *msg, char *base, struct nlattr *attr, struct nlattr *attr2, uc_vm_t *vm)
{
	union { uint8_t u8; uint16_t u16; uint32_t u32; uint64_t u64; size_t sz; } t = { 0 };
	char buf[sizeof("FF:FF:FF:FF:FF:FF")];
	struct ether_addr *ea;
	uc_value_t *v;
	int i;

	switch (spec->type) {
	case DT_U8:
	case DT_S8:
	case DT_U16:
	case DT_U32:
	case DT_S32:
	case DT_U64:
		if (spec->flags & DF_ARRAY) {
			assert(spec->attr != 0);
			assert((nla_len(attr) % dt_sizes[spec->type]) == 0);

			v = ucv_array_new_length(vm, nla_len(attr) / dt_sizes[spec->type]);

			for (i = 0; i < nla_len(attr); i += dt_sizes[spec->type])
				ucv_array_push(v, uc_nl_convert_numval(spec, nla_data(attr) + i));

			return v;
		}
		else if (nla_check_len(attr, dt_sizes[spec->type])) {
			return uc_nl_convert_numval(spec, nla_data(attr));
		}

		return NULL;

	case DT_BOOL:
		if (spec->attr == 0)
			t.u8 = uc_nl_get_struct_member_u8(base, spec->auxdata);
		else if (nla_check_len(attr, sizeof(t.u8)))
			t.u8 = nla_get_u8(attr);

		return ucv_boolean_new(t.u8 != 0);

	case DT_FLAG:
		if (spec->attr == 0)
			t.u8 = uc_nl_get_struct_member_u8(base, spec->auxdata);
		else if (attr != NULL)
			t.u8 = 1;

		return ucv_boolean_new(t.u8 != 0);

	case DT_STRING:
		assert(spec->attr != 0);

		if (!nla_check_len(attr, 1))
			return NULL;

		t.sz = nla_len(attr);

		if (!(spec->flags & DF_BINARY))
			t.sz -= 1;

		return ucv_string_new_length(nla_data(attr), t.sz);

	case DT_NETDEV:
		if (spec->attr == 0)
			t.u32 = uc_nl_get_struct_member_u32(base, spec->auxdata);
		else if (nla_check_len(attr, sizeof(t.u32)))
			t.u32 = nla_get_u32(attr);

		if (if_indextoname(t.u32, buf))
			return ucv_string_new(buf);

		return NULL;

	case DT_LLADDR:
		assert(spec->attr != 0);

		if (!nla_check_len(attr, sizeof(*ea)))
			return NULL;

		ea = nla_data(attr);

		snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
			ea->ether_addr_octet[0], ea->ether_addr_octet[1],
			ea->ether_addr_octet[2], ea->ether_addr_octet[3],
			ea->ether_addr_octet[4], ea->ether_addr_octet[5]);

		return ucv_string_new(buf);

	case DT_INADDR:
		assert(spec->attr != 0);

		if (!nla_check_len(attr, sizeof(struct in_addr)) ||
		    !inet_ntop(AF_INET, nla_data(attr), buf, sizeof(buf)))
			return NULL;

		return ucv_string_new(buf);

	case DT_NESTED:
		if (spec->flags & DF_ARRAY) {
			const uc_nl_nested_spec_t *nested = spec->auxdata;

			assert(nested != NULL);
			assert(nested->headsize > 0);
			assert((nla_len(attr) % nested->headsize) == 0);

			v = ucv_array_new_length(vm, nla_len(attr) / nested->headsize);

			for (i = 0; i < nla_len(attr); i += nested->headsize) {
				uc_value_t *item = ucv_object_new(vm);

				ucv_array_push(v, item);

				bool rv = uc_nl_convert_attrs(msg,
					nla_data(attr) + i, nla_len(attr) - i, nested->headsize,
					nested->attrs, nested->nattrs, vm, item);

				if (!rv) {
					ucv_put(v);

					return NULL;
				}
			}

			return v;
		}

		return uc_nl_convert_rta_nested(spec, msg, attr, vm);

	case DT_HT_MCS:
		return uc_nl_convert_rta_ht_mcs(spec, msg, attr, vm);

	case DT_HT_CAP:
		return uc_nl_convert_rta_ht_cap(spec, msg, attr, vm);

	case DT_VHT_MCS:
		return uc_nl_convert_rta_vht_mcs(spec, msg, attr, vm);

	case DT_HE_MCS:
		return uc_nl_convert_rta_he_mcs(spec, msg, attr, attr2, vm);

	case DT_IE:
		return uc_nl_convert_rta_ie(spec, msg, attr, vm);

	default:
		assert(0);
	}

	return NULL;
}


typedef struct {
	uc_resource_t resource;
	struct nl_sock *sock;
	struct nl_sock *evsock;
	struct nl_cache *cache;
	struct uloop_fd evsock_fd;
	struct nl_cb *evsock_cb;
} nl80211_conn_t;

typedef enum {
	STATE_UNREPLIED,
	STATE_CONTINUE,
	STATE_REPLIED,
	STATE_ERROR
} reply_state_t;

typedef struct {
	reply_state_t state;
	uc_vm_t *vm;
	uc_value_t *res;
	bool merge_phy_info;
	bool single_phy_info;
	const uc_nl_nested_spec_t *spec;
} request_state_t;


static nl80211_conn_t *
uc_nl_conn_ctx(uc_vm_t *vm)
{
	nl80211_conn_t *conn = (void *)uc_vm_registry_get(vm, "nl80211.connection");

	if (ucv_type((uc_value_t *)conn) != UC_RESOURCE) {
		conn = xalloc(sizeof(*conn));
		conn->resource.header.type = UC_RESOURCE;
		conn->resource.header.refcount = 1;
		conn->resource.data = conn;

		uc_vm_registry_set(vm, "nl80211.connection", &conn->resource.header);
	}

	return conn;
}

static uc_value_t *
uc_nl_error(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *last_error, *msg;
	uc_stringbuf_t *buf;
	const char *s;
	int code;

	last_error = uc_vm_registry_get(vm, "nl80211.error");
	code = last_error ? ucv_int64_get(ucv_array_get(last_error, 0)) : 0;
	msg = ucv_array_get(last_error, 1);

	if (code == 0)
		return NULL;

	buf = ucv_stringbuf_new();

	if (code == NLE_FAILURE && msg) {
		ucv_stringbuf_addstr(buf, ucv_string_get(msg), ucv_string_length(msg));
	}
	else {
		s = nl_geterror(code);

		ucv_stringbuf_addstr(buf, s, strlen(s));

		if (msg) {
			ucv_stringbuf_append(buf, ": ");
			ucv_stringbuf_addstr(buf,
				ucv_string_get(msg), ucv_string_length(msg));
		}
	}

	set_error(vm, 0, NULL);

	return ucv_stringbuf_finish(buf);
}

static int
cb_done(struct nl_msg *msg, void *arg)
{
	request_state_t *s = arg;

	s->state = STATE_REPLIED;

	return NL_STOP;
}

static void
deep_merge_array(uc_value_t *dest, uc_value_t *src);

static void
deep_merge_object(uc_value_t *dest, uc_value_t *src);

static void
deep_merge_array(uc_value_t *dest, uc_value_t *src)
{
	uc_value_t *e, *v;
	size_t i;

	if (ucv_type(dest) == UC_ARRAY && ucv_type(src) == UC_ARRAY) {
		for (i = 0; i < ucv_array_length(src); i++) {
			e = ucv_array_get(dest, i);
			v = ucv_array_get(src, i);

			if (!e)
				ucv_array_set(dest, i, ucv_get(v));
			else if (ucv_type(v) == UC_ARRAY)
				deep_merge_array(e, v);
			else if (ucv_type(v) == UC_OBJECT)
				deep_merge_object(e, v);
		}
	}
}

static void
deep_merge_object(uc_value_t *dest, uc_value_t *src)
{
	uc_value_t *e;
	bool exists;

	if (ucv_type(dest) == UC_OBJECT && ucv_type(src) == UC_OBJECT) {
		ucv_object_foreach(src, k, v) {
			e = ucv_object_get(dest, k, &exists);

			if (!exists)
				ucv_object_add(dest, k, ucv_get(v));
			else if (ucv_type(v) == UC_ARRAY)
				deep_merge_array(e, v);
			else if (ucv_type(v) == UC_OBJECT)
				deep_merge_object(e, v);
		}
	}
}

static int
cb_reply(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = nlmsg_data(hdr);
	request_state_t *s = arg;
	uc_value_t *o, *idx;
	int64_t i;
	bool rv;

	o = ucv_object_new(s->vm);

	rv = uc_nl_convert_attrs(msg,
		genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
		0, s->spec->attrs, s->spec->nattrs, s->vm, o);

	if (rv) {
		if (hdr->nlmsg_flags & NLM_F_MULTI) {
			if (s->merge_phy_info && s->single_phy_info) {
				if (!s->res) {
					s->res = o;
				}
				else {
					deep_merge_object(s->res, o);
					ucv_put(o);
				}
			}
			else if (s->merge_phy_info) {
				idx = ucv_object_get(o, "wiphy", NULL);
				i = idx ? ucv_int64_get(idx) : -1;

				if (i >= 0) {
					if (!s->res)
						s->res = ucv_array_new(s->vm);

					idx = ucv_array_get(s->res, i);

					if (idx) {
						deep_merge_object(idx, o);
						ucv_put(o);
					}
					else {
						ucv_array_set(s->res, i, o);
					}
				}
			}
			else {
				if (!s->res)
					s->res = ucv_array_new(s->vm);

				ucv_array_push(s->res, o);
			}
		}
		else {
			s->res = o;
		}
	}
	else {
		ucv_put(o);
	}

	s->state = STATE_CONTINUE;

	return NL_SKIP;
}

static bool
uc_nl_connect_sock(uc_vm_t *vm, struct nl_sock **sk, bool nonblocking)
{
	int err, fd;

	if (*sk)
		return true;

	*sk = nl_socket_alloc();

	if (!*sk) {
		set_error(vm, NLE_NOMEM, NULL);
		goto err;
	}

	err = genl_connect(*sk);

	if (err != 0) {
		set_error(vm, err, NULL);
		goto err;
	}

	fd = nl_socket_get_fd(*sk);

	if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC) < 0) {
		set_error(vm, NLE_FAILURE, "unable to set FD_CLOEXEC flag on socket: %s", strerror(errno));
		goto err;
	}

	if (nonblocking) {
		err = nl_socket_set_nonblocking(*sk);

		if (err != 0) {
			set_error(vm, err, NULL);
			goto err;
		}
	}

	return true;

err:
	if (*sk) {
		nl_socket_free(*sk);
		*sk = NULL;
	}

	return false;
}

static int
uc_nl_find_family_id(nl80211_conn_t *conn, const char *name)
{
	struct genl_family *fam;

	if (!conn->cache && genl_ctrl_alloc_cache(conn->sock, &conn->cache))
		return -NLE_NOMEM;

	fam = genl_ctrl_search_by_name(conn->cache, name);

	if (!fam)
		return -NLE_OBJ_NOTFOUND;

	return genl_family_get_id(fam);
}

static int
cb_errno(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *ret = arg;

	*ret = err->error;

	return NL_STOP;
}

static int
cb_ack(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	*ret = 0;

	return NL_STOP;
}

static int
cb_subscribe(struct nl_msg *msg, void *arg)
{
	struct nlattr *nla, *tb[CTRL_ATTR_MAX + 1], *grp[CTRL_ATTR_MCAST_GRP_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct { int id; const char *group; } *ret = arg;
	int rem;

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return NL_SKIP;

	nla_for_each_nested(nla, tb[CTRL_ATTR_MCAST_GROUPS], rem) {
		nla_parse(grp, CTRL_ATTR_MCAST_GRP_MAX, nla_data(nla), nla_len(nla), NULL);

		if (!grp[CTRL_ATTR_MCAST_GRP_NAME] || !grp[CTRL_ATTR_MCAST_GRP_ID])
			continue;

		if (strncmp(nla_data(grp[CTRL_ATTR_MCAST_GRP_NAME]),
		            ret->group, nla_len(grp[CTRL_ATTR_MCAST_GRP_NAME])))
			continue;

		ret->id = nla_get_u32(grp[CTRL_ATTR_MCAST_GRP_ID]);

		break;
	}

	return NL_SKIP;
}

static bool
uc_nl_subscribe(uc_vm_t *vm, struct nl_sock *sk, const char *family, const char *group)
{
	struct { int id; const char *group; } grp = { -NLE_OBJ_NOTFOUND, group };
	nl80211_conn_t *conn = uc_nl_conn_ctx(vm);
	struct nl_msg *msg;
	struct nl_cb *cb;
	int id, ret, err;

	if (!uc_nl_connect_sock(vm, &conn->sock, false))
		return NULL;

	msg = nlmsg_alloc();

	if (!msg)
		err_return(NLE_NOMEM, NULL);

	id = uc_nl_find_family_id(conn, "nlctrl");

	if (id < 0)
		err_return(-id, NULL);

	genlmsg_put(msg, 0, 0, id, 0, 0, CTRL_CMD_GETFAMILY, 0);
	nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family);

	cb = nl_cb_alloc(NL_CB_DEFAULT);

	if (!cb) {
		nlmsg_free(msg);
		err_return(NLE_NOMEM, NULL);
	}

	nl_send_auto_complete(conn->sock, msg);

	ret = 1;
	err = 0;

	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, cb_ack, &ret);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_errno, &err);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_subscribe, &grp);

	while (ret > 0 && err == 0)
		nl_recvmsgs(conn->sock, cb);

	nlmsg_free(msg);
	nl_cb_put(cb);

	if (err > 0)
		err_return(NLE_RANGE, "Illegal error code %d in netlink reply", err);

	if (err < 0)
		err_return(-nl_syserr2nlerr(err), NULL);

	if (grp.id < 0)
		err_return(grp.id, NULL);

	err = nl_socket_add_membership(sk, grp.id);

	if (err != 0)
		err_return(err, NULL);

	return true;
}


struct waitfor_ctx {
	uint8_t cmd;
	uc_vm_t *vm;
	uc_value_t *res;
	uint32_t cmds[NL80211_CMDS_BITMAP_SIZE];
};

static uc_value_t *
uc_nl_prepare_event(uc_vm_t *vm, struct nl_msg *msg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = nlmsg_data(hdr);
	uc_value_t *o = ucv_object_new(vm);

	if (!uc_nl_convert_attrs(msg, genlmsg_attrdata(gnlh, 0),
		genlmsg_attrlen(gnlh, 0), 0,
		nl80211_msg.attrs, nl80211_msg.nattrs, vm, o)) {
		ucv_put(o);
		return NULL;
	}

	return o;
}

#define uc_nl_listener_foreach(vm, r_, i_, l_) \
	for (uc_value_t *r_ = uc_vm_registry_get(vm, "nl80211.registry"); \
	     r_ != NULL; \
	     r_ = NULL) \
	for (size_t i_ = 0, i_##_length_ = ucv_array_length(r_); \
	     i_##_length_ > 0; \
	     i_##_length_ = 0) \
	for (uc_nl_listener_t *l_ = ucv_resource_data(ucv_array_get(r_, 0), \
	                                              "nl80211.listener"); \
	     i_ < i_##_length_; \
	     l_ = ucv_resource_data(ucv_array_get(r_, ++i_), "nl80211.listener"))

static int
cb_listener_event(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = nlmsg_data(hdr);
	uc_vm_t *vm = arg;
	nl80211_conn_t *conn = uc_nl_conn_ctx(vm);

	if (!conn->evsock_fd.registered)
		return NL_SKIP;

	uc_nl_listener_foreach(vm, registry, i, listener) {
		if (!listener)
			continue;

		if (gnlh->cmd > NL80211_CMD_MAX ||
			!(listener->cmds[gnlh->cmd / 32] & (1 << (gnlh->cmd % 32))))
			continue;

		if (!ucv_is_callable(listener->callback))
			continue;

		uc_value_t *data = uc_nl_prepare_event(vm, msg);
		if (!data)
			return NL_SKIP;

		uc_value_t *o = ucv_object_new(vm);
		ucv_object_add(o, "cmd", ucv_int64_new(gnlh->cmd));
		ucv_object_add(o, "msg", data);

		uc_vm_stack_push(vm, ucv_get(&listener->resource.header));
		uc_vm_stack_push(vm, ucv_get(listener->callback));
		uc_vm_stack_push(vm, o);

		if (uc_vm_call(vm, true, 1) != EXCEPTION_NONE) {
			uloop_end();
			return NL_STOP;
		}

		ucv_put(uc_vm_stack_pop(vm));
	}

	return NL_SKIP;
}

static int
cb_event(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = nlmsg_data(hdr);
	struct waitfor_ctx *s = arg;
	uc_value_t *o;

	cb_listener_event(msg, s->vm);

	if (gnlh->cmd > NL80211_CMD_MAX ||
	    !(s->cmds[gnlh->cmd / 32] & (1 << (gnlh->cmd % 32))))
		return NL_SKIP;

	o = uc_nl_prepare_event(s->vm, msg);
	if (o)
		s->res = o;

	s->cmd = gnlh->cmd;

	return NL_SKIP;
}

static int
cb_seq(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static bool
uc_nl_fill_cmds(uint32_t *cmd_bits, uc_value_t *cmds)
{
	if (ucv_type(cmds) == UC_ARRAY) {
		for (size_t i = 0; i < ucv_array_length(cmds); i++) {
			int64_t n = ucv_int64_get(ucv_array_get(cmds, i));

			if (errno || n < 0 || n > NL80211_CMD_MAX)
				return false;

			cmd_bits[n / 32] |= (1 << (n % 32));
		}
	}
	else if (ucv_type(cmds) == UC_INTEGER) {
		int64_t n = ucv_int64_get(cmds);

		if (errno || n < 0 || n > 255)
			return false;

		cmd_bits[n / 32] |= (1 << (n % 32));
	}
	else if (!cmds)
		memset(cmd_bits, 0xff, NL80211_CMDS_BITMAP_SIZE * sizeof(*cmd_bits));
	else
		return false;

	return true;
}

static bool
uc_nl_evsock_init(uc_vm_t *vm, nl80211_conn_t *conn)
{
	if (conn->evsock)
		return true;

	if (!uc_nl_connect_sock(vm, &conn->evsock, true))
		return false;

	if (!uc_nl_subscribe(vm, conn->evsock, "nl80211", "config") ||
	    !uc_nl_subscribe(vm, conn->evsock, "nl80211", "scan") ||
	    !uc_nl_subscribe(vm, conn->evsock, "nl80211", "regulatory") ||
	    !uc_nl_subscribe(vm, conn->evsock, "nl80211", "mlme") ||
	    !uc_nl_subscribe(vm, conn->evsock, "nl80211", "vendor") ||
	    !uc_nl_subscribe(vm, conn->evsock, "nl80211", "nan")) {
		nl_socket_free(conn->evsock);
		conn->evsock = NULL;
		return false;
	}

	return true;
}

static uc_value_t *
uc_nl_waitfor(uc_vm_t *vm, size_t nargs)
{
	nl80211_conn_t *conn = uc_nl_conn_ctx(vm);
	struct pollfd pfd = { .events = POLLIN };
	uc_value_t *cmds = uc_fn_arg(0);
	uc_value_t *timeout = uc_fn_arg(1);
	uc_value_t *rv = NULL;
	struct waitfor_ctx ctx = { .vm = vm };
	struct nl_cb *cb;
	int ms = -1, err;

	if (timeout) {
		int64_t n = ucv_int64_get(timeout);

		if (ucv_type(timeout) != UC_INTEGER || n < INT32_MIN || n > INT32_MAX)
			err_return(NLE_INVAL, "Invalid timeout specified");

		ms = (int)n;
	}

	if (!uc_nl_fill_cmds(ctx.cmds, cmds))
		err_return(NLE_INVAL, "Invalid command ID specified");

	if (!uc_nl_evsock_init(vm, conn))
		return NULL;

	cb = nl_cb_alloc(NL_CB_DEFAULT);

	if (!cb)
		err_return(NLE_NOMEM, NULL);

	err = 0;

	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, cb_seq, NULL);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_event, &ctx);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_errno, &err);

	pfd.fd = nl_socket_get_fd(conn->evsock);

	if (poll(&pfd, 1, ms) == 1) {
		while (err == 0 && ctx.cmd == 0)
			nl_recvmsgs(conn->evsock, cb);
	}

	nl_cb_put(cb);

	if (ctx.cmd) {
		rv = ucv_object_new(vm);

		ucv_object_add(rv, "cmd", ucv_int64_new(ctx.cmd));
		ucv_object_add(rv, "msg", ctx.res);

		return rv;
	}
	else if (err > 0) {
		err_return(NLE_RANGE, "Illegal error code %d in netlink reply", err);
	}
	else if (err < 0) {
		err_return(-nl_syserr2nlerr(err), NULL);
	}
	else {
		err_return(NLE_FAILURE, "No event received");
	}
}

static uc_value_t *
uc_nl_request(uc_vm_t *vm, size_t nargs)
{
	nl80211_conn_t *conn = uc_nl_conn_ctx(vm);
	request_state_t st = { .vm = vm };
	uc_value_t *cmd = uc_fn_arg(0);
	uc_value_t *flags = uc_fn_arg(1);
	uc_value_t *payload = uc_fn_arg(2);
	uint16_t flagval = 0;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int id, cid, err;

	if (ucv_type(cmd) != UC_INTEGER || ucv_int64_get(cmd) < 0 ||
	    (flags != NULL && ucv_type(flags) != UC_INTEGER) ||
	    (payload != NULL && ucv_type(payload) != UC_OBJECT))
		err_return(NLE_INVAL, NULL);

	if (flags) {
		if (ucv_int64_get(flags) < 0 || ucv_int64_get(flags) > 0xffff)
			err_return(NLE_INVAL, NULL);
		else
			flagval = (uint16_t)ucv_int64_get(flags);
	}

	if (!uc_nl_connect_sock(vm, &conn->sock, false))
		return NULL;

	msg = nlmsg_alloc();

	if (!msg)
		err_return(NLE_NOMEM, NULL);

	cid = ucv_int64_get(cmd);

	if (cid >= HWSIM_CMD_OFFSET) {
		id = uc_nl_find_family_id(conn, "MAC80211_HWSIM");
		cid -= HWSIM_CMD_OFFSET;
		st.spec = &hwsim_msg;
	}
	else if (cid == NL80211_CMD_GET_WIPHY) {
		id = uc_nl_find_family_id(conn, "nl80211");
		st.spec = &nl80211_msg;
		st.merge_phy_info = true;

		if (ucv_object_get(payload, "wiphy", NULL) != NULL)
			st.single_phy_info = true;

		if (ucv_is_truish(ucv_object_get(payload, "split_wiphy_dump", NULL)))
			flagval |= NLM_F_DUMP;
	}
	else {
		id = uc_nl_find_family_id(conn, "nl80211");
		st.spec = &nl80211_msg;
	}

	if (id < 0)
		err_return(-id, NULL);

	genlmsg_put(msg, 0, 0, id, 0, flagval, cid, 0);

	if (!uc_nl_parse_attrs(msg, nlmsg_data(nlmsg_hdr(msg)), st.spec->attrs, st.spec->nattrs, vm, payload)) {
		nlmsg_free(msg);

		return NULL;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);

	if (!cb) {
		nlmsg_free(msg);
		err_return(NLE_NOMEM, NULL);
	}

	err = 0;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_reply, &st);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_done, &st);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, cb_done, &st);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_errno, &err);

	nl_send_auto_complete(conn->sock, msg);

	while (err == 0 && st.state < STATE_REPLIED)
		nl_recvmsgs(conn->sock, cb);

	nlmsg_free(msg);
	nl_cb_put(cb);

	if (err > 0)
		err_return(NLE_RANGE, "Illegal error code %d in netlink reply", err);

	if (err < 0)
		err_return(-nl_syserr2nlerr(err), NULL);

	switch (st.state) {
	case STATE_REPLIED:
		return st.res;

	case STATE_UNREPLIED:
		return ucv_boolean_new(true);

	default:
		set_error(vm, NLE_FAILURE, "Interrupted reply");

		return ucv_boolean_new(false);
	}
}

static void
uc_nl_listener_cb(struct uloop_fd *fd, unsigned int events)
{
	nl80211_conn_t *conn = container_of(fd, nl80211_conn_t, evsock_fd);

	nl_recvmsgs(conn->evsock, conn->evsock_cb);
}

static uc_value_t *
uc_nl_listener(uc_vm_t *vm, size_t nargs)
{
	nl80211_conn_t *conn = uc_nl_conn_ctx(vm);
	struct uloop_fd *fd = &conn->evsock_fd;
	uc_value_t *cb_func = uc_fn_arg(0);
	uc_value_t *cmds = uc_fn_arg(1);

	if (!ucv_is_callable(cb_func)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Invalid callback");
		return NULL;
	}

	if (!uc_nl_evsock_init(vm, conn))
		return NULL;

	if (!fd->registered) {
		fd->fd = nl_socket_get_fd(conn->evsock);
		fd->cb = uc_nl_listener_cb;
		uloop_fd_add(fd, ULOOP_READ);
	}

	if (!conn->evsock_cb) {
		struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);

		if (!cb)
			err_return(NLE_NOMEM, NULL);

		nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, cb_seq, NULL);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_listener_event, vm);
		conn->evsock_cb = cb;
	}

	uc_nl_listener_t *listener = xalloc(sizeof(*listener));

	listener->resource.header.type = UC_RESOURCE;
	listener->resource.header.refcount = 1;
	listener->resource.type = ucv_resource_type_lookup(vm, "nl80211.listener");
	listener->resource.data = listener;
	listener->callback = ucv_get(cb_func);

	if (!uc_nl_fill_cmds(listener->cmds, cmds)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Invalid command ID");
		ucv_put(&listener->resource.header);

		return NULL;
	}

	uc_nl_listener_foreach(vm, registry, i, listener) {
		if (listener == NULL) {
			ucv_array_set(registry, i, ucv_get(&listener->resource.header));
			goto out;
		}
	}

	ucv_array_push(uc_vm_registry_get(vm, "nl80211.registry"),
		ucv_get(&listener->resource.header));

out:
	return &listener->resource.header;
}

static void
uc_nl_listener_free(void *arg)
{
	uc_nl_listener_t *listener = arg;

	if (!listener)
		return;

	ucv_put(listener->callback);
}

static uc_value_t *
uc_nl_listener_set_commands(uc_vm_t *vm, size_t nargs)
{
	uc_nl_listener_t *listener = uc_fn_thisval("nl80211.listener");
	uc_value_t *cmds = uc_fn_arg(0);

	if (!listener)
		return NULL;

	memset(listener->cmds, 0, sizeof(listener->cmds));
	if (!uc_nl_fill_cmds(listener->cmds, cmds))
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Invalid command ID");

	return NULL;
}

static uc_value_t *
uc_nl_listener_close(uc_vm_t *vm, size_t nargs)
{
	uc_nl_listener_t **lptr = uc_fn_this("nl80211.listener");

	if (!lptr || !*lptr)
		return NULL;

	uc_nl_listener_foreach(vm, registry, i, listener) {
		if (listener == *lptr) {
			ucv_array_set(registry, i, NULL);
			break;
		}
	}

	uc_nl_listener_free(*lptr);

	*lptr = NULL;

	return NULL;
}


static void
register_constants(uc_vm_t *vm, uc_value_t *scope)
{
	uc_value_t *c = ucv_object_new(vm);

#define ADD_CONST(x) ucv_object_add(c, #x, ucv_int64_new(x))

	ADD_CONST(NLM_F_ACK);
	ADD_CONST(NLM_F_ACK_TLVS);
	ADD_CONST(NLM_F_APPEND);
	ADD_CONST(NLM_F_ATOMIC);
	ADD_CONST(NLM_F_CAPPED);
	ADD_CONST(NLM_F_CREATE);
	ADD_CONST(NLM_F_DUMP);
	ADD_CONST(NLM_F_DUMP_FILTERED);
	ADD_CONST(NLM_F_DUMP_INTR);
	ADD_CONST(NLM_F_ECHO);
	ADD_CONST(NLM_F_EXCL);
	ADD_CONST(NLM_F_MATCH);
	ADD_CONST(NLM_F_MULTI);
	ADD_CONST(NLM_F_NONREC);
	ADD_CONST(NLM_F_REPLACE);
	ADD_CONST(NLM_F_REQUEST);
	ADD_CONST(NLM_F_ROOT);

	ADD_CONST(NL80211_CMD_GET_WIPHY);
	ADD_CONST(NL80211_CMD_SET_WIPHY);
	ADD_CONST(NL80211_CMD_NEW_WIPHY);
	ADD_CONST(NL80211_CMD_DEL_WIPHY);
	ADD_CONST(NL80211_CMD_GET_INTERFACE);
	ADD_CONST(NL80211_CMD_SET_INTERFACE);
	ADD_CONST(NL80211_CMD_NEW_INTERFACE);
	ADD_CONST(NL80211_CMD_DEL_INTERFACE);
	ADD_CONST(NL80211_CMD_GET_KEY);
	ADD_CONST(NL80211_CMD_SET_KEY);
	ADD_CONST(NL80211_CMD_NEW_KEY);
	ADD_CONST(NL80211_CMD_DEL_KEY);
	ADD_CONST(NL80211_CMD_GET_BEACON);
	ADD_CONST(NL80211_CMD_SET_BEACON);
	ADD_CONST(NL80211_CMD_START_AP);
	ADD_CONST(NL80211_CMD_NEW_BEACON);
	ADD_CONST(NL80211_CMD_STOP_AP);
	ADD_CONST(NL80211_CMD_DEL_BEACON);
	ADD_CONST(NL80211_CMD_GET_STATION);
	ADD_CONST(NL80211_CMD_SET_STATION);
	ADD_CONST(NL80211_CMD_NEW_STATION);
	ADD_CONST(NL80211_CMD_DEL_STATION);
	ADD_CONST(NL80211_CMD_GET_MPATH);
	ADD_CONST(NL80211_CMD_SET_MPATH);
	ADD_CONST(NL80211_CMD_NEW_MPATH);
	ADD_CONST(NL80211_CMD_DEL_MPATH);
	ADD_CONST(NL80211_CMD_SET_BSS);
	ADD_CONST(NL80211_CMD_SET_REG);
	ADD_CONST(NL80211_CMD_REQ_SET_REG);
	ADD_CONST(NL80211_CMD_GET_MESH_CONFIG);
	ADD_CONST(NL80211_CMD_SET_MESH_CONFIG);
	ADD_CONST(NL80211_CMD_GET_REG);
	ADD_CONST(NL80211_CMD_GET_SCAN);
	ADD_CONST(NL80211_CMD_TRIGGER_SCAN);
	ADD_CONST(NL80211_CMD_NEW_SCAN_RESULTS);
	ADD_CONST(NL80211_CMD_SCAN_ABORTED);
	ADD_CONST(NL80211_CMD_REG_CHANGE);
	ADD_CONST(NL80211_CMD_AUTHENTICATE);
	ADD_CONST(NL80211_CMD_ASSOCIATE);
	ADD_CONST(NL80211_CMD_DEAUTHENTICATE);
	ADD_CONST(NL80211_CMD_DISASSOCIATE);
	ADD_CONST(NL80211_CMD_MICHAEL_MIC_FAILURE);
	ADD_CONST(NL80211_CMD_REG_BEACON_HINT);
	ADD_CONST(NL80211_CMD_JOIN_IBSS);
	ADD_CONST(NL80211_CMD_LEAVE_IBSS);
	ADD_CONST(NL80211_CMD_TESTMODE);
	ADD_CONST(NL80211_CMD_CONNECT);
	ADD_CONST(NL80211_CMD_ROAM);
	ADD_CONST(NL80211_CMD_DISCONNECT);
	ADD_CONST(NL80211_CMD_SET_WIPHY_NETNS);
	ADD_CONST(NL80211_CMD_GET_SURVEY);
	ADD_CONST(NL80211_CMD_NEW_SURVEY_RESULTS);
	ADD_CONST(NL80211_CMD_SET_PMKSA);
	ADD_CONST(NL80211_CMD_DEL_PMKSA);
	ADD_CONST(NL80211_CMD_FLUSH_PMKSA);
	ADD_CONST(NL80211_CMD_REMAIN_ON_CHANNEL);
	ADD_CONST(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL);
	ADD_CONST(NL80211_CMD_SET_TX_BITRATE_MASK);
	ADD_CONST(NL80211_CMD_REGISTER_FRAME);
	ADD_CONST(NL80211_CMD_REGISTER_ACTION);
	ADD_CONST(NL80211_CMD_FRAME);
	ADD_CONST(NL80211_CMD_ACTION);
	ADD_CONST(NL80211_CMD_FRAME_TX_STATUS);
	ADD_CONST(NL80211_CMD_ACTION_TX_STATUS);
	ADD_CONST(NL80211_CMD_SET_POWER_SAVE);
	ADD_CONST(NL80211_CMD_GET_POWER_SAVE);
	ADD_CONST(NL80211_CMD_SET_CQM);
	ADD_CONST(NL80211_CMD_NOTIFY_CQM);
	ADD_CONST(NL80211_CMD_SET_CHANNEL);
	ADD_CONST(NL80211_CMD_SET_WDS_PEER);
	ADD_CONST(NL80211_CMD_FRAME_WAIT_CANCEL);
	ADD_CONST(NL80211_CMD_JOIN_MESH);
	ADD_CONST(NL80211_CMD_LEAVE_MESH);
	ADD_CONST(NL80211_CMD_UNPROT_DEAUTHENTICATE);
	ADD_CONST(NL80211_CMD_UNPROT_DISASSOCIATE);
	ADD_CONST(NL80211_CMD_NEW_PEER_CANDIDATE);
	ADD_CONST(NL80211_CMD_GET_WOWLAN);
	ADD_CONST(NL80211_CMD_SET_WOWLAN);
	ADD_CONST(NL80211_CMD_START_SCHED_SCAN);
	ADD_CONST(NL80211_CMD_STOP_SCHED_SCAN);
	ADD_CONST(NL80211_CMD_SCHED_SCAN_RESULTS);
	ADD_CONST(NL80211_CMD_SCHED_SCAN_STOPPED);
	ADD_CONST(NL80211_CMD_SET_REKEY_OFFLOAD);
	ADD_CONST(NL80211_CMD_PMKSA_CANDIDATE);
	ADD_CONST(NL80211_CMD_TDLS_OPER);
	ADD_CONST(NL80211_CMD_TDLS_MGMT);
	ADD_CONST(NL80211_CMD_UNEXPECTED_FRAME);
	ADD_CONST(NL80211_CMD_PROBE_CLIENT);
	ADD_CONST(NL80211_CMD_REGISTER_BEACONS);
	ADD_CONST(NL80211_CMD_UNEXPECTED_4ADDR_FRAME);
	ADD_CONST(NL80211_CMD_SET_NOACK_MAP);
	ADD_CONST(NL80211_CMD_CH_SWITCH_NOTIFY);
	ADD_CONST(NL80211_CMD_START_P2P_DEVICE);
	ADD_CONST(NL80211_CMD_STOP_P2P_DEVICE);
	ADD_CONST(NL80211_CMD_CONN_FAILED);
	ADD_CONST(NL80211_CMD_SET_MCAST_RATE);
	ADD_CONST(NL80211_CMD_SET_MAC_ACL);
	ADD_CONST(NL80211_CMD_RADAR_DETECT);
	ADD_CONST(NL80211_CMD_GET_PROTOCOL_FEATURES);
	ADD_CONST(NL80211_CMD_UPDATE_FT_IES);
	ADD_CONST(NL80211_CMD_FT_EVENT);
	ADD_CONST(NL80211_CMD_CRIT_PROTOCOL_START);
	ADD_CONST(NL80211_CMD_CRIT_PROTOCOL_STOP);
	ADD_CONST(NL80211_CMD_GET_COALESCE);
	ADD_CONST(NL80211_CMD_SET_COALESCE);
	ADD_CONST(NL80211_CMD_CHANNEL_SWITCH);
	ADD_CONST(NL80211_CMD_VENDOR);
	ADD_CONST(NL80211_CMD_SET_QOS_MAP);
	ADD_CONST(NL80211_CMD_ADD_TX_TS);
	ADD_CONST(NL80211_CMD_DEL_TX_TS);
	ADD_CONST(NL80211_CMD_GET_MPP);
	ADD_CONST(NL80211_CMD_JOIN_OCB);
	ADD_CONST(NL80211_CMD_LEAVE_OCB);
	ADD_CONST(NL80211_CMD_CH_SWITCH_STARTED_NOTIFY);
	ADD_CONST(NL80211_CMD_TDLS_CHANNEL_SWITCH);
	ADD_CONST(NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH);

	ADD_CONST(HWSIM_CMD_REGISTER),
	ADD_CONST(HWSIM_CMD_FRAME),
	ADD_CONST(HWSIM_CMD_TX_INFO_FRAME),
	ADD_CONST(HWSIM_CMD_NEW_RADIO),
	ADD_CONST(HWSIM_CMD_DEL_RADIO),
	ADD_CONST(HWSIM_CMD_GET_RADIO),
	ADD_CONST(HWSIM_CMD_ADD_MAC_ADDR),
	ADD_CONST(HWSIM_CMD_DEL_MAC_ADDR),
	ADD_CONST(HWSIM_CMD_START_PMSR),
	ADD_CONST(HWSIM_CMD_ABORT_PMSR),
	ADD_CONST(HWSIM_CMD_REPORT_PMSR),

	ADD_CONST(NL80211_IFTYPE_ADHOC);
	ADD_CONST(NL80211_IFTYPE_STATION);
	ADD_CONST(NL80211_IFTYPE_AP);
	ADD_CONST(NL80211_IFTYPE_AP_VLAN);
	ADD_CONST(NL80211_IFTYPE_WDS);
	ADD_CONST(NL80211_IFTYPE_MONITOR);
	ADD_CONST(NL80211_IFTYPE_MESH_POINT);
	ADD_CONST(NL80211_IFTYPE_P2P_CLIENT);
	ADD_CONST(NL80211_IFTYPE_P2P_GO);
	ADD_CONST(NL80211_IFTYPE_P2P_DEVICE);
	ADD_CONST(NL80211_IFTYPE_OCB);

	ucv_object_add(scope, "const", c);
};

static const uc_function_list_t global_fns[] = {
	{ "error",		uc_nl_error },
	{ "request",	uc_nl_request },
	{ "waitfor",	uc_nl_waitfor },
	{ "listener",	uc_nl_listener },
};


static const uc_function_list_t listener_fns[] = {
	{ "set_commands",	uc_nl_listener_set_commands },
	{ "close",			uc_nl_listener_close },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

	uc_type_declare(vm, "nl80211.listener", listener_fns, uc_nl_listener_free);
	uc_vm_registry_set(vm, "nl80211.registry", ucv_array_new(vm));

	register_constants(vm, scope);
}
