#include <Python.h>
#include <ctype.h>
#include <errno.h>

#include <netlink/cache.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>

#define NL_CB_me NL_CB_DEFAULT

static char *act2str(int act) {
#define C2S(x)                                                                 \
  case x:                                                                      \
    return &#x[7];
  switch (act) {
    C2S(NL_ACT_UNSPEC)
    C2S(NL_ACT_NEW)
    C2S(NL_ACT_DEL)
    C2S(NL_ACT_GET)
    C2S(NL_ACT_SET)
    C2S(NL_ACT_CHANGE)
  default:
	  return "???";
  }
#undef C2S
}

static void dump_link_info(int act, struct rtnl_link *link, PyObject* cb) {
	printf("link act: %-6s ifindex: %2d ifname: %s flags: 0x%08x type: %d\n",
	       act2str(act), rtnl_link_get_ifindex(link), rtnl_link_get_name(link),
	       rtnl_link_get_flags(link), rtnl_link_get_arptype(link));
}

static void cb_link(struct nl_cache *cache, struct nl_object *ob, int act,
                    void *data) {
	dump_link_info(act, (struct rtnl_link *)ob, (PyObject*)data);
}

static void e_link(struct nl_object *ob, void *data) {
	dump_link_info(NL_ACT_NEW, (struct rtnl_link *)ob, (PyObject*)data);
}


struct rtnetlink_listener {
	PyObject_HEAD
	struct nl_cache_mngr *mngr;
	PyObject *callback;
	PyObject *exc_tp, *exc_val, *exc_tb;
};

static void call_link_callback(
	int act,
	struct rtnl_link *link,
	struct rtnetlink_listener* listener)
{
	printf("link act: %-6s ifindex: %2d ifname: %s flags: 0x%08x type: %d\n",
	       act2str(act), rtnl_link_get_ifindex(link), rtnl_link_get_name(link),
	       rtnl_link_get_flags(link), rtnl_link_get_arptype(link));
	if (listener->exc == NULL) {
		PyObject *r = PyObject_CallFunction(listener->callback, "");
		Py_XDECREF(r);
		if (PyErr_Occurred()) {
			PyE
		}
	}
}

static void cb_link(struct nl_cache *cache, struct nl_object *ob, int act,
                    void *data) {
	dump_link_info(act, (struct rtnl_link *)ob, (PyObject*)data);
}

static void e_link(struct nl_object *ob, void *data) {
	dump_link_info(NL_ACT_NEW, (struct rtnl_link *)ob, (PyObject*)data);
}

static void
listener_dealloc(struct rtnetlink_listener *v) {
	PyObject_GC_UnTrack(v);
	Py_DECREF(v->callback);
	nl_cache_mngr_free(v->mngr);
	Py_XDECREF(v->exc);
	PyObject_GC_Del(v);
}

static PyTypeObject ListenerType;

static PyObject *
listener_new(PyTypeObject *type, PyObject *args, PyObject *kw)
{
	PyObject* cb;
	struct nl_cache_mngr *mngr;
	struct nl_cache *link_cache;
	int r;

	if (!_PyArg_NoKeywords("listener()", kw))
		return NULL;

	if (!PyArg_UnpackTuple(args, "listener", 1, 1, &cb))
		return NULL;

	r = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
	if (r < 0) {
		PyErr_Format(PyExc_MemoryError, "nl_cache_mngr_alloc failed %d", r);
		return NULL;
	}

	r = rtnl_link_alloc_cache(NULL, AF_UNSPEC, &link_cache);
	if (r < 0) {
		nl_cache_mngr_free(mngr);
		PyErr_Format(PyExc_MemoryError, "rtnl_link_alloc_cache_add failed %d\n", r);
		return NULL;
	}

	struct rtnetlink_listener* listener = (struct rtnetlink_listener*)type->tp_alloc(type, 0);

	listener->mngr = mngr;


	Py_INCREF(cb);
	listener->callback = cb;

	r = nl_cache_mngr_add_cache(mngr, link_cache, cb_link, listener);
	if (r < 0) {
		Py_DECREF(listener);
		PyErr_Format(PyExc_RuntimeError, "nl_cache_mngr_add_cache failed %d\n", r);
		return NULL;
	}

	return (PyObject*)listener;
}

static PyTypeObject ListenerType = {
	.ob_base = PyVarObject_HEAD_INIT(&PyType_Type, 0)
	.tp_name = "listener",
	.tp_basicsize = sizeof(struct rtnetlink_listener),

	.tp_dealloc = (destructor)listener_dealloc,
	.tp_new = listener_new,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
};

//static char buf[100];

//static void dump_addr_info(int act, struct rtnl_addr *addr) {
//  struct nl_addr *local = rtnl_addr_get_local(addr);
//  printf("addr act: %-6s ifindex: %2d local: %s\n", act2str(act),
//         rtnl_addr_get_ifindex(addr), nl_addr2str(local, buf, sizeof(buf)));
//}
//
//static void cb_addr(struct nl_cache *cache, struct nl_object *ob, int act,
//                    void *data) {
//  dump_addr_info(act, (struct rtnl_addr *)ob);
//}
//
//static void e_addr(struct nl_object *ob, void *data) {
//  dump_addr_info(NL_ACT_NEW, (struct rtnl_addr *)ob);
//}

struct nl_cache *add_link_cache(
	struct nl_cache_mngr *mngr,
	PyObject* cb) {
  struct nl_cache *link_cache;
  int r;

  r = rtnl_link_alloc_cache(NULL, AF_UNSPEC, &link_cache);
  if (r < 0) {
    fprintf(stderr, "rtnl_link_alloc_cache_add failed %d\n", r);
    exit(1);
  }

  r = nl_cache_mngr_add_cache(mngr, link_cache, cb_link, cb);
  if (r < 0) {
    fprintf(stderr, "nl_cache_mngr_add_cache failed %d\n", r);
    exit(1);
  }

  return link_cache;
}

//struct nl_cache *add_addr_cache(struct nl_sock *sock,
//                                struct nl_cache_mngr *mngr) {
//  struct nl_cache *addr_cache;
//  int r;
//
//  r = rtnl_addr_alloc_cache(sock, &addr_cache);
//  if (r < 0) {
//    fprintf(stderr, "rtnl_addr_alloc_cache_add failed %d\n", r);
//    exit(1);
//  }
//
//  r = nl_cache_mngr_add_cache(mngr, addr_cache, cb_addr, NULL);
//  if (r < 0) {
//    fprintf(stderr, "nl_cache_mngr_add_cache failed %d\n", r);
//    exit(1);
//  }
//
//  return addr_cache;
//}

struct nl_cache_mngr *setup_rtnl(PyObject *cb) {
  struct nl_cache_mngr *mngr;
  struct nl_cache *link_cache;
//  struct nl_cache *addr_cache;
  int r;

  r = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
  if (r < 0) {
	  PyErr_Format(PyExc_MemoryError, "nl_cache_mngr_alloc failed %d", r);
	  return NULL;
  }

  link_cache = add_link_cache(mngr, cb);
//  addr_cache = add_addr_cache(sock, mngr);

  nl_cache_foreach(link_cache, e_link, cb);
//  nl_cache_foreach(addr_cache, e_addr, NULL);

  return mngr;
}

struct nl_cache_mngr *rtnl_mngr;

static PyObject *
start_listening(PyObject *self, PyObject *cb)
{

	rtnl_mngr = setup_rtnl(cb);
	if (rtnl_mngr == NULL) {
		return NULL;
	}

	return PyLong_FromLong(nl_cache_mngr_get_fd(rtnl_mngr));
}

static PyObject *
data_ready(PyObject *self, PyObject *cb)
{
        nl_cache_mngr_data_ready(rtnl_mngr);
	Py_RETURN_NONE;
}


static PyMethodDef rtnetlink_methods[] = {
    {"start_listening",  start_listening, METH_VARARGS, "XXX."},
    {"data_ready",  data_ready, METH_NOARGS, "XXX."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef rtnetlink_module = {
   PyModuleDef_HEAD_INIT,
   "_rtnetlink",
   NULL,
   -1,
   rtnetlink_methods,
};

PyMODINIT_FUNC
PyInit__rtnetlink(void)
{
    PyObject *m = PyModule_Create(&rtnetlink_module);

    if (m == NULL)
        return NULL;

    if (PyType_Ready(&ListenerType) < 0)
        return NULL;

    PyModule_AddObject(m, "listener", (PyObject *)&ListenerType);

    return m;
}
