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
	if (listener->exc_typ != NULL || listener->callback == Py_None) {
		return;
	}
	PyObject *arg = PyDict_New();
	PyObject *ob = NULL;
	PyObject *data = NULL;
	if (arg == NULL) {
		goto exit;
	}
	ob = PyUnicode_FromString(act2str(act));
	if (ob == NULL || PyDict_SetItemString(arg, "action", ob) < 0) {
		goto exit;
	}
	Py_DECREF(ob);
	ob = PyDict_New();
	if (ob == NULL || PyDict_SetItemString(arg, "data", ob) < 0) {
		goto exit;
	}
	data = ob;
	ob = PyLong_FromLong(rtnl_link_get_ifindex(link));
	if (ob == NULL || PyDict_SetItemString(data, "ifindex", ob) < 0) {
		goto exit;
	}
	Py_DECREF(ob);
	ob = PyLong_FromLong(rtnl_link_get_flags(link));
	if (ob == NULL || PyDict_SetItemString(data, "flags", ob) < 0) {
		goto exit;
	}
	Py_DECREF(ob);
	ob = PyLong_FromLong(rtnl_link_get_arptype(link));
	if (ob == NULL || PyDict_SetItemString(data, "arptype", ob) < 0) {
		goto exit;
	}
	Py_DECREF(ob);
	if (rtnl_link_get_name(link) != NULL) {
		ob = PyBytes_FromString(rtnl_link_get_name(link));
		if (ob == NULL || PyDict_SetItemString(data, "name", ob) < 0) {
			goto exit;
		}
		Py_DECREF(ob);
	}
	ob = NULL;
	PyObject *r = PyObject_CallMethod(listener->callback, "link_change", "O", arg);
	Py_XDECREF(r);

  exit:
	Py_XDECREF(ob);
	Py_XDECREF(data);
	Py_XDECREF(arg);
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

static void call_addr_callback(
	int act,
	struct rtnl_addr *addr,
	struct Listener* listener)
{
	if (listener->exc_typ != NULL || listener->callback == Py_None) {
		return;
	}
	PyObject *arg = PyDict_New();
	PyObject *ob = NULL;
	PyObject *data = NULL;
	if (arg == NULL) {
		goto exit;
	}
	ob = PyUnicode_FromString(act2str(act));
	if (ob == NULL || PyDict_SetItemString(arg, "action", ob) < 0) {
		goto exit;
	}
	Py_DECREF(ob);
	ob = PyDict_New();
	if (ob == NULL || PyDict_SetItemString(arg, "data", ob) < 0) {
		goto exit;
	}
	data = ob;
	ob = PyLong_FromLong(rtnl_addr_get_ifindex(addr));
	if (ob == NULL || PyDict_SetItemString(data, "ifindex", ob) < 0) {
		goto exit;
	}
	Py_DECREF(ob);
	struct nl_addr *local = rtnl_addr_get_local(addr);
	if (local != NULL) {
		char buf[100];
		ob = PyBytes_FromString(nl_addr2str(local, buf, 100));
		if (ob == NULL || PyDict_SetItemString(data, "local", ob) < 0) {
			goto exit;
		}
		Py_DECREF(ob);
	}
	ob = NULL;
	PyObject *r = PyObject_CallMethod(listener->callback, "addr_change", "O", arg);
	Py_XDECREF(r);

  exit:
	Py_XDECREF(ob);
	Py_XDECREF(data);
	Py_XDECREF(arg);
	if (PyErr_Occurred()) {
		PyErr_Fetch(&listener->exc_typ, &listener->exc_val, &listener->exc_tb);
	}
}

static void _cb_addr(struct nl_cache *cache, struct nl_object *ob, int act,
                    void *data) {
	call_addr_callback(act, (struct rtnl_addr *)ob, (struct Listener*)data);
}

static void _e_addr(struct nl_object *ob, void *data) {
	call_addr_callback(NL_ACT_NEW, (struct rtnl_addr *)ob, (struct Listener*)data);
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
	int r;

	r = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
	if (r < 0) {
		PyErr_Format(PyExc_MemoryError, "nl_cache_mngr_alloc failed %d", r);
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
	struct nl_cache *link_cache, *addr_cache;
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

	r = rtnl_addr_alloc_cache(NULL, &addr_cache);
	if (r < 0) {
		PyErr_Format(PyExc_MemoryError, "rtnl_link_alloc_cache failed %d\n", r);
		return NULL;
	}

	r = nl_cache_mngr_add_cache(listener->mngr, addr_cache, _cb_addr, listener);
	if (r < 0) {
		nl_cache_free(addr_cache);
		PyErr_Format(PyExc_RuntimeError, "nl_cache_mngr_add_cache failed %d\n", r);
		return NULL;
	}

	nl_cache_foreach(link_cache, _e_link, self);
	nl_cache_foreach(addr_cache, _e_addr, self);

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

static struct PyModuleDef rtnetlink_module = {
   PyModuleDef_HEAD_INIT,
   "_rtnetlink",
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
