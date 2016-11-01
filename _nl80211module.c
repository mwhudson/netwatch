#include <Python.h>
#include <ctype.h>
#include <errno.h>

#include <linux/genetlink.h>
#include <linux/nl80211.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#define NL_CB_me NL_CB_DEFAULT

struct Listener {
	PyObject_HEAD
	PyObject *callback;
	struct nl_sock* event_sock;
	struct nl_sock* genl_sock;
	PyObject *exc_typ, *exc_val, *exc_tb;
	int err;
	int nl80211_id;
};


static void
listener_dealloc(PyObject *self) {
	struct Listener* v = (struct Listener*)self;
	PyObject_GC_UnTrack(v);
	Py_CLEAR(v->callback);
	Py_CLEAR(v->exc_typ);
	Py_CLEAR(v->exc_val);
	Py_CLEAR(v->exc_tb);
	nl_socket_free(v->event_sock);
	PyObject_GC_Del(v);
}

static int
listener_traverse(PyObject *self, visitproc visit, void *arg)
{
	struct Listener* v = (struct Listener*)self;
	Py_VISIT(v->callback);
	Py_VISIT(v->exc_typ);
	Py_VISIT(v->exc_val);
	Py_VISIT(v->exc_tb);
	return 0;
}

static PyTypeObject ListenerType;

static int ack_handler(struct nl_msg *msg, void *arg) {
	int *err = arg;
	*err = 0;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                         void *arg) {
	int *ret = arg;
	*ret = err->error;
	return NL_SKIP;
}

static int no_seq_check(struct nl_msg *msg, void *arg) { return NL_OK; }

struct nl80211_multicast_ids {
	int mlme_id;
	int scan_id;
};

static int family_handler(struct nl_msg *msg, void *arg)
{
	struct nl80211_multicast_ids *res = arg;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *mcgrp;
	int i;

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return NL_SKIP;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
		struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
		char *name;
		int len;
		nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp), nla_len(mcgrp),
			  NULL);
		if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] || !tb2[CTRL_ATTR_MCAST_GRP_ID]) {
			continue;
		}
		name = nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]);
		len = nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME]);
		if (strncmp(name, "scan", len) == 0) {
			res->scan_id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
		}
		if (strncmp(name, "mlme", len) == 0) {
			res->mlme_id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
		}
	};

	return NL_SKIP;
}

static int send_and_recv(
	struct nl_sock *genl_sock,
	struct nl_msg *msg,
	int (*valid_handler)(struct nl_msg *, void *),
	void *valid_data)
{
	struct nl_cb *cb;
	int err = -ENOMEM;

	cb = nl_cb_alloc(NL_CB_me);
	if (!cb)
		goto out;

	err = nl_send_auto(genl_sock, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	if (valid_handler) {
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, valid_data);
	}

	while (err > 0) {
		int res = nl_recvmsgs(genl_sock, cb);
		if (res < 0) {
			fprintf(stderr, "nl_recvmsgs failed");
		}
	}
  out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return err;
}

static int nl_get_multicast_ids(
	struct nl_sock *genl_sock,
	struct nl80211_multicast_ids *res)
{
	struct nl_msg *msg;
	int ret = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;
	genlmsg_put(msg, 0, 0, genl_ctrl_resolve(genl_sock, "nlctrl"), 0, 0,
		    CTRL_CMD_GETFAMILY, 0);
	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, "nl80211");

	ret = send_and_recv(genl_sock, msg, family_handler, res);
	msg = NULL;

  nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

static const char *nl80211_command_to_string(enum nl80211_commands cmd) {
#define C2S(x)					\
	case x:					\
		return #x
	switch (cmd) {
		C2S(NL80211_CMD_UNSPEC);
		C2S(NL80211_CMD_GET_WIPHY);
		C2S(NL80211_CMD_SET_WIPHY);
		C2S(NL80211_CMD_NEW_WIPHY);
		C2S(NL80211_CMD_DEL_WIPHY);
		C2S(NL80211_CMD_GET_INTERFACE);
		C2S(NL80211_CMD_SET_INTERFACE);
		C2S(NL80211_CMD_NEW_INTERFACE);
		C2S(NL80211_CMD_DEL_INTERFACE);
		C2S(NL80211_CMD_GET_KEY);
		C2S(NL80211_CMD_SET_KEY);
		C2S(NL80211_CMD_NEW_KEY);
		C2S(NL80211_CMD_DEL_KEY);
		C2S(NL80211_CMD_GET_BEACON);
		C2S(NL80211_CMD_SET_BEACON);
		C2S(NL80211_CMD_START_AP);
		C2S(NL80211_CMD_STOP_AP);
		C2S(NL80211_CMD_GET_STATION);
		C2S(NL80211_CMD_SET_STATION);
		C2S(NL80211_CMD_NEW_STATION);
		C2S(NL80211_CMD_DEL_STATION);
		C2S(NL80211_CMD_GET_MPATH);
		C2S(NL80211_CMD_SET_MPATH);
		C2S(NL80211_CMD_NEW_MPATH);
		C2S(NL80211_CMD_DEL_MPATH);
		C2S(NL80211_CMD_SET_BSS);
		C2S(NL80211_CMD_SET_REG);
		C2S(NL80211_CMD_REQ_SET_REG);
		C2S(NL80211_CMD_GET_MESH_CONFIG);
		C2S(NL80211_CMD_SET_MESH_CONFIG);
		C2S(NL80211_CMD_SET_MGMT_EXTRA_IE);
		C2S(NL80211_CMD_GET_REG);
		C2S(NL80211_CMD_GET_SCAN);
		C2S(NL80211_CMD_TRIGGER_SCAN);
		C2S(NL80211_CMD_NEW_SCAN_RESULTS);
		C2S(NL80211_CMD_SCAN_ABORTED);
		C2S(NL80211_CMD_REG_CHANGE);
		C2S(NL80211_CMD_AUTHENTICATE);
		C2S(NL80211_CMD_ASSOCIATE);
		C2S(NL80211_CMD_DEAUTHENTICATE);
		C2S(NL80211_CMD_DISASSOCIATE);
		C2S(NL80211_CMD_MICHAEL_MIC_FAILURE);
		C2S(NL80211_CMD_REG_BEACON_HINT);
		C2S(NL80211_CMD_JOIN_IBSS);
		C2S(NL80211_CMD_LEAVE_IBSS);
		C2S(NL80211_CMD_TESTMODE);
		C2S(NL80211_CMD_CONNECT);
		C2S(NL80211_CMD_ROAM);
		C2S(NL80211_CMD_DISCONNECT);
		C2S(NL80211_CMD_SET_WIPHY_NETNS);
		C2S(NL80211_CMD_GET_SURVEY);
		C2S(NL80211_CMD_NEW_SURVEY_RESULTS);
		C2S(NL80211_CMD_SET_PMKSA);
		C2S(NL80211_CMD_DEL_PMKSA);
		C2S(NL80211_CMD_FLUSH_PMKSA);
		C2S(NL80211_CMD_REMAIN_ON_CHANNEL);
		C2S(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL);
		C2S(NL80211_CMD_SET_TX_BITRATE_MASK);
		C2S(NL80211_CMD_REGISTER_FRAME);
		C2S(NL80211_CMD_FRAME);
		C2S(NL80211_CMD_FRAME_TX_STATUS);
		C2S(NL80211_CMD_SET_POWER_SAVE);
		C2S(NL80211_CMD_GET_POWER_SAVE);
		C2S(NL80211_CMD_SET_CQM);
		C2S(NL80211_CMD_NOTIFY_CQM);
		C2S(NL80211_CMD_SET_CHANNEL);
		C2S(NL80211_CMD_SET_WDS_PEER);
		C2S(NL80211_CMD_FRAME_WAIT_CANCEL);
		C2S(NL80211_CMD_JOIN_MESH);
		C2S(NL80211_CMD_LEAVE_MESH);
		C2S(NL80211_CMD_UNPROT_DEAUTHENTICATE);
		C2S(NL80211_CMD_UNPROT_DISASSOCIATE);
		C2S(NL80211_CMD_NEW_PEER_CANDIDATE);
		C2S(NL80211_CMD_GET_WOWLAN);
		C2S(NL80211_CMD_SET_WOWLAN);
		C2S(NL80211_CMD_START_SCHED_SCAN);
		C2S(NL80211_CMD_STOP_SCHED_SCAN);
		C2S(NL80211_CMD_SCHED_SCAN_RESULTS);
		C2S(NL80211_CMD_SCHED_SCAN_STOPPED);
		C2S(NL80211_CMD_SET_REKEY_OFFLOAD);
		C2S(NL80211_CMD_PMKSA_CANDIDATE);
		C2S(NL80211_CMD_TDLS_OPER);
		C2S(NL80211_CMD_TDLS_MGMT);
		C2S(NL80211_CMD_UNEXPECTED_FRAME);
		C2S(NL80211_CMD_PROBE_CLIENT);
		C2S(NL80211_CMD_REGISTER_BEACONS);
		C2S(NL80211_CMD_UNEXPECTED_4ADDR_FRAME);
		C2S(NL80211_CMD_SET_NOACK_MAP);
		C2S(NL80211_CMD_CH_SWITCH_NOTIFY);
		C2S(NL80211_CMD_START_P2P_DEVICE);
		C2S(NL80211_CMD_STOP_P2P_DEVICE);
		C2S(NL80211_CMD_CONN_FAILED);
		C2S(NL80211_CMD_SET_MCAST_RATE);
		C2S(NL80211_CMD_SET_MAC_ACL);
		C2S(NL80211_CMD_RADAR_DETECT);
		C2S(NL80211_CMD_GET_PROTOCOL_FEATURES);
		C2S(NL80211_CMD_UPDATE_FT_IES);
		C2S(NL80211_CMD_FT_EVENT);
		C2S(NL80211_CMD_CRIT_PROTOCOL_START);
		C2S(NL80211_CMD_CRIT_PROTOCOL_STOP);
		C2S(NL80211_CMD_GET_COALESCE);
		C2S(NL80211_CMD_SET_COALESCE);
		C2S(NL80211_CMD_CHANNEL_SWITCH);
		C2S(NL80211_CMD_VENDOR);
		C2S(NL80211_CMD_SET_QOS_MAP);
	default:
		return "NL80211_CMD_UNKNOWN";
	}
#undef C2S
}

static int event_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	int ifidx = -1;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_IFINDEX]) {
		ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
	}

	printf("wlan ifidx: %d cmd: %s\n", ifidx,
	       nl80211_command_to_string(gnlh->cmd));

	if (gnlh->cmd == NL80211_CMD_NEW_INTERFACE) {
		if (ifidx < 0) {
			return NL_SKIP;
		}
		printf("nl802011 new interface ifidx: %d\n", ifidx);
//		nl80211_trigger_scan(sock, ifidx);
	}
//	if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
//		if (ifidx < 0) {
//			return NL_SKIP;
//		}
//		printf("nl802011 new scan results on ifidx: %d\n", ifidx);
//		struct nl_msg *msg;
//		msg = nlmsg_alloc();
//		if (!msg)
//			return NL_SKIP;
//		genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
//		NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifidx);
//
//		send_and_recv(sock, msg, nl80211_scan_handler, NULL);
//		msg = NULL;
//	  nla_put_failure:
//		nlmsg_free(msg);
//	}
//
//	if (tb[NL80211_ATTR_BSS]) {
//		maybe_print_ssid(ifidx, tb[NL80211_ATTR_BSS]);
//	}
//
	return NL_SKIP;
}


static PyObject *
listener_new(PyTypeObject *type, PyObject *args, PyObject *kw)
{
	struct nl_sock *event_sock, *genl_sock;
	struct nl_cb *event_cb;

	struct Listener* listener = (struct Listener*)type->tp_alloc(type, 0);

	event_cb = nl_cb_alloc(NL_CB_me);
	nl_cb_err(event_cb, NL_CB_CUSTOM, error_handler, &listener->err);
	nl_cb_set(event_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &listener->err);
	nl_cb_set(event_cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &listener->err);
	nl_cb_set(event_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, &listener->err);
	nl_cb_set(event_cb, NL_CB_VALID, NL_CB_CUSTOM, event_handler, listener);

	event_sock = nl_socket_alloc_cb(event_cb);
	if (event_sock == NULL) {
		PyErr_SetString(PyExc_MemoryError, "nl_socket_alloc_cb");
		return NULL;
	}

	genl_sock = nl_socket_alloc();
	if (genl_sock == NULL) {
		nl_socket_free(event_sock);
		PyErr_SetString(PyExc_MemoryError, "nl_socket_alloc");
		return NULL;
	}
	// XXX is this really needed?
	nl_socket_set_cb(genl_sock, nl_cb_alloc(NL_CB_me));

	listener->event_sock = event_sock;
	listener->genl_sock = genl_sock;

	Py_INCREF(Py_None);
	listener->callback = Py_None;

	return (PyObject*)listener;
}

static int
listener_init(PyObject *self, PyObject *args, PyObject *kw)
{
	PyObject* cb;

	char *kwlist[] = {"callback", 0};

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O:listener", kwlist, &cb))
		return -1;

	struct Listener* listener = (struct Listener*)self;

	Py_CLEAR(listener->callback);
	Py_INCREF(cb);
	listener->callback = cb;

	return 0;
}

static PyObject*
maybe_restore(struct Listener* listener) {
	if (listener->exc_typ != NULL) {
		PyErr_Restore(listener->exc_typ, listener->exc_val, listener->exc_tb);
		listener->exc_typ = listener->exc_val = listener->exc_tb = NULL;
		return NULL;
	}
	if (listener->err != 0) {
		PyErr_Format(PyExc_RuntimeError, "random netlink error: %d", listener->err);
	}
	Py_RETURN_NONE;
}

static PyObject*
listener_start(PyObject *self, PyObject* args)
{
	int r;
	struct nl80211_multicast_ids ids;
	struct Listener* listener = (struct Listener*)self;

	r = genl_connect(listener->genl_sock);
	if (r < 0) {
		PyErr_Format(PyExc_RuntimeError, "genl_connect failed: %d", r);
		return NULL;
	}
	listener->nl80211_id = genl_ctrl_resolve(listener->genl_sock, "nl80211");
	r = nl_get_multicast_ids(listener->genl_sock, &ids);
	if (r < 0) {
		PyErr_Format(PyExc_RuntimeError, "nl_get_multicast_ids failed: %d", r);
		return NULL;
	}

	r = genl_connect(listener->event_sock);
	if (r < 0) {
		PyErr_Format(PyExc_RuntimeError, "genl_connect failed: %d", r);
		return NULL;
	}
	r = nl_socket_set_nonblocking(listener->event_sock);
	if (r < 0) {
		PyErr_Format(PyExc_RuntimeError, "nl_socket_set_nonblocking failed: %d", r);
		return NULL;
	}
	r = nl_socket_add_memberships(listener->event_sock, ids.mlme_id, ids.scan_id, 0);
	if (r < 0) {
		PyErr_Format(PyExc_RuntimeError, "nl_socket_add_memberships: %d", r);
		return NULL;
	}

	return maybe_restore(listener);
}

static PyObject*
listener_fileno(PyObject *self, PyObject* args)
{
	struct Listener* listener = (struct Listener*)self;
	return PyLong_FromLong(nl_socket_get_fd(listener->event_sock));
}

static PyObject*
listener_data_ready(PyObject *self, PyObject* args)
{
	struct Listener* listener = (struct Listener*)self;

	nl_recvmsgs_default(listener->event_sock);

	return maybe_restore(listener);
}

static PyMethodDef ListenerMethods[] = {
	{"start", listener_start, METH_NOARGS, "XXX."},
	{"fileno", listener_fileno, METH_NOARGS, "XXX."},
	{"data_ready", listener_data_ready, METH_NOARGS, "XXX."},
	{},
};

static PyTypeObject ListenerType = {
	.ob_base = PyVarObject_HEAD_INIT(&PyType_Type, 0)
	.tp_name = "_nl80211.listener",
	.tp_basicsize = sizeof(struct Listener),

	.tp_dealloc = listener_dealloc,
	.tp_new = listener_new,
	.tp_init = listener_init,
	.tp_traverse = listener_traverse,

	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_methods = ListenerMethods,
};

static struct PyModuleDef nl80211_module = {
   PyModuleDef_HEAD_INIT,
   "_nl80211",
};

PyMODINIT_FUNC
PyInit__nl80211(void)
{
    PyObject *m = PyModule_Create(&nl80211_module);

    if (m == NULL)
        return NULL;

    if (PyType_Ready(&ListenerType) < 0)
        return NULL;

    PyModule_AddObject(m, "listener", (PyObject *)&ListenerType);

    return m;
}
