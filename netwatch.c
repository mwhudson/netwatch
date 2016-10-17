#include <errno.h>

#include <netlink/cache.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>

#include <linux/genetlink.h>

static void dump_link_info(int act, struct rtnl_link *link) {
  printf("act: %d ifindex: %d ifname: %s\n", act, rtnl_link_get_ifindex(link),
         rtnl_link_get_name(link));
}

static void cb_link(struct nl_cache *cache, struct nl_object *ob, int act,
                    void *data) {
  dump_link_info(act, (struct rtnl_link *)ob);
}

static void e_link(struct nl_object *ob, void *data) {
  dump_link_info(NL_ACT_NEW, (struct rtnl_link *)ob);
}

static char buf[100];

static void dump_addr_info(int act, struct rtnl_addr *addr) {
  struct nl_addr *local = rtnl_addr_get_local(addr);
  printf("act: %d ifindex: %d local: %s\n", act, rtnl_addr_get_ifindex(addr),
         nl_addr2str(local, buf, sizeof(buf)));
}

static void cb_addr(struct nl_cache *cache, struct nl_object *ob, int act,
                    void *data) {
  dump_addr_info(act, (struct rtnl_addr *)ob);
}

static void e_addr(struct nl_object *ob, void *data) {
  dump_addr_info(NL_ACT_NEW, (struct rtnl_addr *)ob);
}

struct nl_cache *add_link_cache(struct nl_sock *sock,
                                struct nl_cache_mngr *mngr) {
  struct nl_cache *link_cache;
  int r;

  r = rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache);
  if (r < 0) {
    fprintf(stderr, "rtnl_link_alloc_cache_add failed %d\n", r);
    exit(1);
  }

  r = nl_cache_mngr_add_cache(mngr, link_cache, cb_link, NULL);
  if (r < 0) {
    fprintf(stderr, "nl_cache_mngr_add_cache failed %d\n", r);
    exit(1);
  }

  return link_cache;
}

struct nl_cache *add_addr_cache(struct nl_sock *sock,
                                struct nl_cache_mngr *mngr) {
  struct nl_cache *addr_cache;
  int r;

  r = rtnl_addr_alloc_cache(sock, &addr_cache);
  if (r < 0) {
    fprintf(stderr, "rtnl_addr_alloc_cache_add failed %d\n", r);
    exit(1);
  }

  r = nl_cache_mngr_add_cache(mngr, addr_cache, cb_addr, NULL);
  if (r < 0) {
    fprintf(stderr, "nl_cache_mngr_add_cache failed %d\n", r);
    exit(1);
  }

  return addr_cache;
}

struct nl_cache_mngr *setup_rtnl(struct nl_sock *sock) {
  struct nl_cache_mngr *mngr;
  struct nl_cache *link_cache;
  struct nl_cache *addr_cache;
  int r;

  r = nl_cache_mngr_alloc(sock, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
  if (r < 0) {
    fprintf(stderr, "nl_cache_mngr_alloc failed %d\n", r);
    exit(1);
  }

  link_cache = add_link_cache(sock, mngr);
  addr_cache = add_addr_cache(sock, mngr);

  nl_cache_foreach(link_cache, e_link, NULL);
  nl_cache_foreach(addr_cache, e_addr, NULL);

  return mngr;
}

struct nl80211_multicast_ids {
  int mlme_id;
  int scan_id;
};

static int family_handler(struct nl_msg *msg, void *arg) {
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
    printf("family %s id %d\n", name, nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]));
    if (strncmp(name, "scan", len) == 0) {
	    res->scan_id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
    }
    if (strncmp(name, "mlme", len) == 0) {
	    res->mlme_id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
    }
  };

  return NL_SKIP;
}

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

static int send_and_recv(struct nl_sock *genl_sock, struct nl_msg *msg,
                         int (*valid_handler)(struct nl_msg *, void *),
                         void *valid_data) {
  struct nl_cb *cb;
  int err = -ENOMEM;

  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb)
    goto out;

  err = nl_send_auto(genl_sock, msg);
  if (err < 0)
    goto out;

  err = 1;

  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
//  nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);

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

static int nl_get_multicast_ids(struct nl_sock *genl_sock,   struct nl80211_multicast_ids *res) {
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

static int nl80211_handler(struct nl_msg *msg, void *arg) {
	printf("nl80211_handler\n");
}

struct nl_sock *setup_nl80211(struct nl_sock *sock) {
  struct nl_sock *event_sock;
  struct nl_cb *event_cb;
  int nl80211_id;
  struct nl80211_multicast_ids ids;
  int r;

  r = genl_connect(sock);
  if (r < 0) {
    fprintf(stderr, "genl_connect failed: %d\n", r);
    exit(1);
  }
  nl80211_id = genl_ctrl_resolve(sock, "nl80211");
  if (nl80211_id < 0) {
    fprintf(stderr, "genl_ctrl_resolve(\"nl80211\") failed %d\n", nl80211_id);
    exit(1);
  }
  printf("nl80211_id: %d\n", nl80211_id);
  nl_get_multicast_ids(sock, &ids);
  printf("multicast_ids: mlme: %d, scan: %d\n", ids.mlme_id, ids.scan_id);

  int err;
  event_cb = nl_cb_alloc(NL_CB_DEFAULT);
  nl_cb_err(event_cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(event_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(event_cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
  nl_cb_set(event_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
  nl_cb_set(event_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_handler, NULL);

  event_sock = nl_socket_alloc_cb(event_cb);
  r = genl_connect(event_sock);
  if (r < 0) {
    fprintf(stderr, "genl_connect failed: %d\n", r);
    exit(1);
  }
  r = nl_socket_set_nonblocking(event_sock);
  if (r < 0) {
    fprintf(stderr, "nl_socket_set_nonblocking failed %d\n", r);
    exit(1);
  }
  r = nl_socket_add_memberships(event_sock, ids.mlme_id, ids.scan_id, 0);
  if (r < 0) {
    fprintf(stderr, "nl_socket_add_memberships failed %d\n", r);
    exit(1);
  }

  return event_sock;
}

int main(int argc, char **argv) {
  struct nl_cache_mngr *rtnl_mngr;
  struct nl_sock *rtnl_sock;
  struct nl_sock *genl_sock;
  struct nl_sock *event_sock;
  int r;

  rtnl_sock = nl_socket_alloc();
  if (rtnl_sock == NULL) {
    fprintf(stderr, "nl_socket_alloc failed\n");
    exit(1);
  }

  rtnl_mngr = setup_rtnl(rtnl_sock);

  genl_sock = nl_socket_alloc();
  if (genl_sock == NULL) {
    fprintf(stderr, "nl_socket_alloc failed\n");
    exit(1);
  }
  nl_socket_set_buffer_size(genl_sock, 8192, 8192);
  event_sock = setup_nl80211(genl_sock);

  while (1) {
    r = nl_cache_mngr_poll(rtnl_mngr, 1000);
    if (r < 0) {
      fprintf(stderr, "nl_cache_mngr_poll failed %d\n", r);
      exit(1);
    }
    printf(".\n");
    nl_recvmsgs_default(event_sock);
  }
}
