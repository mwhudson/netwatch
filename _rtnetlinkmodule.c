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
	struct nl_sock *sock,
	struct nl_cache_mngr *mngr,
	PyObject* cb) {
  struct nl_cache *link_cache;
  int r;

  r = rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache);
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

struct nl_cache_mngr *setup_rtnl(struct nl_sock *sock, PyObject *cb) {
  struct nl_cache_mngr *mngr;
  struct nl_cache *link_cache;
//  struct nl_cache *addr_cache;
  int r;

  r = nl_cache_mngr_alloc(sock, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
  if (r < 0) {
	  PyErr_Format(PyExc_MemoryError, "nl_cache_mngr_alloc failed %d", r);
	  return NULL;
  }

  link_cache = add_link_cache(sock, mngr, cb);
//  addr_cache = add_addr_cache(sock, mngr);

  nl_cache_foreach(link_cache, e_link, cb);
//  nl_cache_foreach(addr_cache, e_addr, NULL);

  return mngr;
}

struct nl_cache_mngr *rtnl_mngr;

static PyObject *
start_listening(PyObject *self, PyObject *cb)
{
	struct nl_sock* rtnl_sock;
	rtnl_sock = nl_socket_alloc();
	if (rtnl_sock == NULL) {
		PyErr_SetString(PyExc_MemoryError, "nl_socket_alloc failed");
		return NULL;
	}

	rtnl_mngr = setup_rtnl(rtnl_sock, cb);
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
    return PyModule_Create(&rtnetlink_module);
}
