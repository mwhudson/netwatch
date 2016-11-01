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
	struct nl_sock* nl80211_sock;
	PyObject *exc_typ, *exc_val, *exc_tb;
	int err;
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

static PyObject *
listener_new(PyTypeObject *type, PyObject *args, PyObject *kw)
{
	struct nl_sock *event_sock;
	struct nl_cb *event_cb;

	struct Listener* listener = (struct Listener*)type->tp_alloc(type, 0);

	event_cb = nl_cb_alloc(NL_CB_me);
//	nl_cb_err(event_cb, NL_CB_CUSTOM, error_handler, listener);
//	nl_cb_set(event_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, listener);
//	nl_cb_set(event_cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, listener);
//	nl_cb_set(event_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, listener);
//	nl_cb_set(event_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_handler, listener);

	event_sock = nl_socket_alloc_cb(event_cb);
	if (event_sock == NULL) {
		PyErr_SetString(PyExc_MemoryError, "nl_socket_alloc_cb");
		return NULL;
	}

	listener->event_sock = event_sock;

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
	int r;
	struct Listener* listener = (struct Listener*)self;

	r = genl_connect(listener->event_sock);
	if (r < 0) {
		PyErr_Format(PyExc_RuntimeError, "genl_connect failed: %d\n", r);
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
