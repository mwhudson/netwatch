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

struct Listener {
	PyObject_HEAD
	struct nl_cache_mngr *mngr;
	PyObject *callback;
	PyObject *exc_typ, *exc_val, *exc_tb;
};

static void call_link_callback(
	int act,
	struct rtnl_link *link,
	struct Listener* listener)
{
	printf("link act: %-6s ifindex: %2d ifname: %s flags: 0x%08x type: %d\n",
	       act2str(act), rtnl_link_get_ifindex(link), rtnl_link_get_name(link),
	       rtnl_link_get_flags(link), rtnl_link_get_arptype(link));
	if (listener->exc_typ != NULL || listener->callback == Py_None) {
		return;
	}
	PyObject *arg = PyDict_New();
	if (PyDict_SetItemString(arg, "ifindex", PyLong_FromLong(rtnl_link_get_ifindex(link))) < 0) {
		Py_DECREF(arg);
		goto exit;
	}
	PyObject *r = PyObject_CallMethod(listener->callback, "link_change", "O", arg);
	Py_XDECREF(r);

  exit:
	if (PyErr_Occurred()) {
		PyErr_Fetch(&listener->exc_typ, &listener->exc_val, &listener->exc_tb);
	}
}

static void _cb_link(struct nl_cache *cache, struct nl_object *ob, int act,
                    void *data) {
	call_link_callback(act, (struct rtnl_link *)ob, (struct Listener*)data);
}

static void _e_link(struct nl_object *ob, void *data) {
	call_link_callback(NL_ACT_NEW, (struct rtnl_link *)ob, (struct Listener*)data);
}

static void
listener_dealloc(PyObject *self) {
	struct Listener* v = (struct Listener*)self;
	PyObject_GC_UnTrack(v);
	Py_CLEAR(v->callback);
	nl_cache_mngr_free(v->mngr);
	Py_CLEAR(v->exc_typ);
	Py_CLEAR(v->exc_val);
	Py_CLEAR(v->exc_tb);
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

static PyObject *
listener_new(PyTypeObject *type, PyObject *args, PyObject *kw)
{
	struct nl_cache_mngr *mngr;
	struct nl_cache *link_cache;
	int r;

	r = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
	if (r < 0) {
		PyErr_Format(PyExc_MemoryError, "nl_cache_mngr_alloc failed %d", r);
		return NULL;
	}

	r = rtnl_link_alloc_cache(NULL, AF_UNSPEC, &link_cache);
	if (r < 0) {
		nl_cache_mngr_free(mngr);
		PyErr_Format(PyExc_MemoryError, "rtnl_link_alloc_cache failed %d\n", r);
		return NULL;
	}

	struct Listener* listener = (struct Listener*)type->tp_alloc(type, 0);

	listener->mngr = mngr;

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
	Py_RETURN_NONE;
}

static PyObject*
listener_start(PyObject *self, PyObject* args)
{
	struct nl_cache *link_cache;
	struct Listener* listener = (struct Listener*)self;
	int r;

	r = rtnl_link_alloc_cache(NULL, AF_UNSPEC, &link_cache);
	if (r < 0) {
		PyErr_Format(PyExc_MemoryError, "rtnl_link_alloc_cache failed %d\n", r);
		return NULL;
	}

	r = nl_cache_mngr_add_cache(listener->mngr, link_cache, _cb_link, listener);
	if (r < 0) {
		nl_cache_free(link_cache);
		PyErr_Format(PyExc_RuntimeError, "nl_cache_mngr_add_cache failed %d\n", r);
		return NULL;
	}

	nl_cache_foreach(link_cache, _e_link, self);

	return maybe_restore(listener);
}

static PyObject*
listener_fileno(PyObject *self, PyObject* args)
{
	struct Listener* listener = (struct Listener*)self;
	return PyLong_FromLong(nl_cache_mngr_get_fd(listener->mngr));
}

static PyObject*
listener_data_ready(PyObject *self, PyObject* args)
{
	struct Listener* listener = (struct Listener*)self;
        nl_cache_mngr_data_ready(listener->mngr);
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
	.tp_name = "_rtnetlink.listener",
	.tp_basicsize = sizeof(struct Listener),

	.tp_dealloc = listener_dealloc,
	.tp_new = listener_new,
	.tp_init = listener_init,
	.tp_traverse = listener_traverse,

	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_methods = ListenerMethods,
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

static struct PyModuleDef rtnetlink_module = {
   PyModuleDef_HEAD_INIT,
   "_rtnetlink",
   NULL,
   -1,
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
