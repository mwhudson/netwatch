#include <ctype.h>
#include <errno.h>

#include <netlink/cache.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>

#include <linux/genetlink.h>
#include <linux/nl80211.h>

#include <sys/epoll.h>

int nl80211_id;

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
  }
#undef C2S
}

static void dump_link_info(int act, struct rtnl_link *link) {
  printf("link act: %-6s ifindex: %2d ifname: %s flags: 0x%08x type: %d\n",
         act2str(act), rtnl_link_get_ifindex(link), rtnl_link_get_name(link),
         rtnl_link_get_flags(link), rtnl_link_get_arptype(link));
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
  printf("addr act: %-6s ifindex: %2d local: %s\n", act2str(act),
         rtnl_addr_get_ifindex(addr), nl_addr2str(local, buf, sizeof(buf)));
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

static int nl_get_multicast_ids(struct nl_sock *genl_sock,
                                struct nl80211_multicast_ids *res) {
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
#define C2S(x)                                                                 \
  case x:                                                                      \
    return #x;
  switch (cmd) {
    C2S(NL80211_CMD_UNSPEC)
    C2S(NL80211_CMD_GET_WIPHY)
    C2S(NL80211_CMD_SET_WIPHY)
    C2S(NL80211_CMD_NEW_WIPHY)
    C2S(NL80211_CMD_DEL_WIPHY)
    C2S(NL80211_CMD_GET_INTERFACE)
    C2S(NL80211_CMD_SET_INTERFACE)
    C2S(NL80211_CMD_NEW_INTERFACE)
    C2S(NL80211_CMD_DEL_INTERFACE)
    C2S(NL80211_CMD_GET_KEY)
    C2S(NL80211_CMD_SET_KEY)
    C2S(NL80211_CMD_NEW_KEY)
    C2S(NL80211_CMD_DEL_KEY)
    C2S(NL80211_CMD_GET_BEACON)
    C2S(NL80211_CMD_SET_BEACON)
    C2S(NL80211_CMD_START_AP)
    C2S(NL80211_CMD_STOP_AP)
    C2S(NL80211_CMD_GET_STATION)
    C2S(NL80211_CMD_SET_STATION)
    C2S(NL80211_CMD_NEW_STATION)
    C2S(NL80211_CMD_DEL_STATION)
    C2S(NL80211_CMD_GET_MPATH)
    C2S(NL80211_CMD_SET_MPATH)
    C2S(NL80211_CMD_NEW_MPATH)
    C2S(NL80211_CMD_DEL_MPATH)
    C2S(NL80211_CMD_SET_BSS)
    C2S(NL80211_CMD_SET_REG)
    C2S(NL80211_CMD_REQ_SET_REG)
    C2S(NL80211_CMD_GET_MESH_CONFIG)
    C2S(NL80211_CMD_SET_MESH_CONFIG)
    C2S(NL80211_CMD_SET_MGMT_EXTRA_IE)
    C2S(NL80211_CMD_GET_REG)
    C2S(NL80211_CMD_GET_SCAN)
    C2S(NL80211_CMD_TRIGGER_SCAN)
    C2S(NL80211_CMD_NEW_SCAN_RESULTS)
    C2S(NL80211_CMD_SCAN_ABORTED)
    C2S(NL80211_CMD_REG_CHANGE)
    C2S(NL80211_CMD_AUTHENTICATE)
    C2S(NL80211_CMD_ASSOCIATE)
    C2S(NL80211_CMD_DEAUTHENTICATE)
    C2S(NL80211_CMD_DISASSOCIATE)
    C2S(NL80211_CMD_MICHAEL_MIC_FAILURE)
    C2S(NL80211_CMD_REG_BEACON_HINT)
    C2S(NL80211_CMD_JOIN_IBSS)
    C2S(NL80211_CMD_LEAVE_IBSS)
    C2S(NL80211_CMD_TESTMODE)
    C2S(NL80211_CMD_CONNECT)
    C2S(NL80211_CMD_ROAM)
    C2S(NL80211_CMD_DISCONNECT)
    C2S(NL80211_CMD_SET_WIPHY_NETNS)
    C2S(NL80211_CMD_GET_SURVEY)
    C2S(NL80211_CMD_NEW_SURVEY_RESULTS)
    C2S(NL80211_CMD_SET_PMKSA)
    C2S(NL80211_CMD_DEL_PMKSA)
    C2S(NL80211_CMD_FLUSH_PMKSA)
    C2S(NL80211_CMD_REMAIN_ON_CHANNEL)
    C2S(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL)
    C2S(NL80211_CMD_SET_TX_BITRATE_MASK)
    C2S(NL80211_CMD_REGISTER_FRAME)
    C2S(NL80211_CMD_FRAME)
    C2S(NL80211_CMD_FRAME_TX_STATUS)
    C2S(NL80211_CMD_SET_POWER_SAVE)
    C2S(NL80211_CMD_GET_POWER_SAVE)
    C2S(NL80211_CMD_SET_CQM)
    C2S(NL80211_CMD_NOTIFY_CQM)
    C2S(NL80211_CMD_SET_CHANNEL)
    C2S(NL80211_CMD_SET_WDS_PEER)
    C2S(NL80211_CMD_FRAME_WAIT_CANCEL)
    C2S(NL80211_CMD_JOIN_MESH)
    C2S(NL80211_CMD_LEAVE_MESH)
    C2S(NL80211_CMD_UNPROT_DEAUTHENTICATE)
    C2S(NL80211_CMD_UNPROT_DISASSOCIATE)
    C2S(NL80211_CMD_NEW_PEER_CANDIDATE)
    C2S(NL80211_CMD_GET_WOWLAN)
    C2S(NL80211_CMD_SET_WOWLAN)
    C2S(NL80211_CMD_START_SCHED_SCAN)
    C2S(NL80211_CMD_STOP_SCHED_SCAN)
    C2S(NL80211_CMD_SCHED_SCAN_RESULTS)
    C2S(NL80211_CMD_SCHED_SCAN_STOPPED)
    C2S(NL80211_CMD_SET_REKEY_OFFLOAD)
    C2S(NL80211_CMD_PMKSA_CANDIDATE)
    C2S(NL80211_CMD_TDLS_OPER)
    C2S(NL80211_CMD_TDLS_MGMT)
    C2S(NL80211_CMD_UNEXPECTED_FRAME)
    C2S(NL80211_CMD_PROBE_CLIENT)
    C2S(NL80211_CMD_REGISTER_BEACONS)
    C2S(NL80211_CMD_UNEXPECTED_4ADDR_FRAME)
    C2S(NL80211_CMD_SET_NOACK_MAP)
    C2S(NL80211_CMD_CH_SWITCH_NOTIFY)
    C2S(NL80211_CMD_START_P2P_DEVICE)
    C2S(NL80211_CMD_STOP_P2P_DEVICE)
    C2S(NL80211_CMD_CONN_FAILED)
    C2S(NL80211_CMD_SET_MCAST_RATE)
    C2S(NL80211_CMD_SET_MAC_ACL)
    C2S(NL80211_CMD_RADAR_DETECT)
    C2S(NL80211_CMD_GET_PROTOCOL_FEATURES)
    C2S(NL80211_CMD_UPDATE_FT_IES)
    C2S(NL80211_CMD_FT_EVENT)
    C2S(NL80211_CMD_CRIT_PROTOCOL_START)
    C2S(NL80211_CMD_CRIT_PROTOCOL_STOP)
    C2S(NL80211_CMD_GET_COALESCE)
    C2S(NL80211_CMD_SET_COALESCE)
    C2S(NL80211_CMD_CHANNEL_SWITCH)
    C2S(NL80211_CMD_VENDOR)
    C2S(NL80211_CMD_SET_QOS_MAP)
  default:
    return "NL80211_CMD_UNKNOWN";
  }
#undef C2S
}

static char *nl80211_get_ie(char *ies, size_t ies_len, char ie) {
  char *end, *pos;

  if (ies == NULL)
    return NULL;

  pos = ies;
  end = ies + ies_len;

  while (pos + 1 < end) {
    if (pos + 2 + pos[1] > end)
      break;
    if (pos[0] == ie)
      return pos;
    pos += 2 + pos[1];
  }

  return NULL;
}

static void bindump(char *label, char *data, int len) {
  printf("%s: [", label);
  char *p = data;
  int l = 0;
  while (l < len) {
    printf("%02hhx", *p);
    if (isgraph(*p)) {
      printf("%c", *p);
    } else {
      printf("-");
    }
    l++;
    p++;
  }
  printf("]\n");
}

static void maybe_print_ssid(int ifindex, struct nlattr *data) {
  struct nlattr *bss[NL80211_BSS_MAX + 1];
  static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
          [NL80211_BSS_INFORMATION_ELEMENTS] = {},
          [NL80211_BSS_STATUS] = {.type = NLA_U32}, [NL80211_BSS_BSSID] = {},
  };
  if (nla_parse_nested(bss, NL80211_BSS_MAX, data, bss_policy))
    return;
  char *cstatus = "no status";
  if (bss[NL80211_BSS_STATUS]) {
    int status = -1;
    status = nla_get_u32(bss[NL80211_BSS_STATUS]);
    switch (status) {
    case NL80211_BSS_STATUS_ASSOCIATED:
      cstatus = "Connected";
      break;
    case NL80211_BSS_STATUS_AUTHENTICATED:
      cstatus = "Authenticated";
      break;
    case NL80211_BSS_STATUS_IBSS_JOINED:
      cstatus = "Joined";
      break;
    }
  }
  char *ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  int ie_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  // bindump("ies", ie, ie_len);
  char *ssid = nl80211_get_ie(ie, ie_len, 0);
  int ssid_len = ssid[1];
  char *ssid_str = malloc(ssid_len + 1);
  memcpy(ssid_str, ssid + 2, ssid_len);
  ssid_str[ssid_len] = 0;
  if (ssid != NULL) {
    printf("ifindex: %d ssid: %-32s (%s)\n", ifindex, ssid_str, cstatus);
  }
}

static int nl80211_scan_handler(struct nl_msg *msg, void *arg) {
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  int ifidx = -1;

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  if (tb[NL80211_ATTR_IFINDEX]) {
    ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
  }

  if (ifidx < 0) {
    return NL_SKIP;
  }

  if (tb[NL80211_ATTR_BSS]) {
    maybe_print_ssid(ifidx, tb[NL80211_ATTR_BSS]);
  }

  return NL_SKIP;
}
static int nl80211_handler(struct nl_msg *msg, void *arg);
static int nl80211_trigger_scan(struct nl_sock *sock, int ifidx) {
  struct nl_msg *msg;
  struct nl_msg *ssids = NULL;
  msg = nlmsg_alloc();
  if (!msg) {
    goto nla_put_failure;
  }
  printf("triggering scan on %d\n", ifidx);
  genlmsg_put(msg, 0, 0, nl80211_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifidx);
  ssids = nlmsg_alloc();
  if (!ssids) {
    goto nla_put_failure;
  }
  NLA_PUT(ssids, 1, 0, "");
  nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);

  send_and_recv(sock, msg, nl80211_handler, sock);
  printf("triggered scan on %d\n", ifidx);
  msg = NULL;
nla_put_failure:
  nlmsg_free(msg);
  nlmsg_free(ssids);
  return NL_SKIP;
}
static int nl80211_handler(struct nl_msg *msg, void *arg) {
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  int ifidx = -1;
  struct i802_bss *bss;
  long long wdev_id = 0;
  int wdev_id_set = 0;
  struct nlattr *nl;
  int rem;
  struct nl_sock *sock = arg;

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
    nl80211_trigger_scan(sock, ifidx);
  }
  if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
    if (ifidx < 0) {
      return NL_SKIP;
    }
    printf("nl802011 new scan results on ifidx: %d\n", ifidx);
    struct nl_msg *msg;
    msg = nlmsg_alloc();
    if (!msg)
      return NL_SKIP;
    genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifidx);

    send_and_recv(sock, msg, nl80211_scan_handler, NULL);
    msg = NULL;
  nla_put_failure:
    nlmsg_free(msg);
  }

  if (tb[NL80211_ATTR_BSS]) {
    maybe_print_ssid(ifidx, tb[NL80211_ATTR_BSS]);
  }

  return NL_SKIP;
}

struct nl_sock *setup_nl80211(struct nl_sock *sock) {
  struct nl_sock *event_sock;
  struct nl_cb *event_cb;
  struct nl80211_multicast_ids ids;
  int r;

  r = genl_connect(sock);
  if (r < 0) {
    fprintf(stderr, "genl_connect failed: %d\n", r);
    exit(1);
  }
  nl80211_id = genl_ctrl_resolve(sock, "nl80211");

  nl_get_multicast_ids(sock, &ids);

  int err;
  event_cb = nl_cb_alloc(NL_CB_me);
  nl_cb_err(event_cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(event_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(event_cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
  nl_cb_set(event_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
  nl_cb_set(event_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_handler, sock);

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

  struct nl_msg *msg;
  msg = nlmsg_alloc();
  if (!msg)
    return NULL;
  genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE,
              0);

  send_and_recv(sock, msg, nl80211_handler, sock);
  msg = NULL;

  return event_sock;
}

int main(int argc, char **argv) {
  printf("%d: %s\n", 32, nl80211_command_to_string(32));
  struct nl_cache_mngr *rtnl_mngr;
  struct nl_sock *rtnl_sock;
  struct nl_sock *genl_sock;
  struct nl_sock *event_sock;
  int r, n;
  int rtnl_fd, nl80211_fd, conn_sock, nfds, epollfd;
#define MAX_EVENTS 10
  struct epoll_event ev, events[MAX_EVENTS];

  rtnl_sock = nl_socket_alloc();
  if (rtnl_sock == NULL) {
    fprintf(stderr, "nl_socket_alloc failed\n");
    exit(1);
  }

  rtnl_mngr = setup_rtnl(rtnl_sock);

  genl_sock = nl_socket_alloc();
  nl_socket_set_cb(genl_sock, nl_cb_alloc(NL_CB_me));
  if (genl_sock == NULL) {
    fprintf(stderr, "nl_socket_alloc failed\n");
    exit(1);
  }
  nl_socket_set_buffer_size(genl_sock, 8192, 8192);
  event_sock = setup_nl80211(genl_sock);

  rtnl_fd = nl_cache_mngr_get_fd(rtnl_mngr);
  nl80211_fd = nl_socket_get_fd(event_sock);

  epollfd = epoll_create1(0);
  if (epollfd == -1) {
    perror("epoll_create1");
    exit(1);
  }
  ev.events = EPOLLIN;
  ev.data.fd = rtnl_fd;
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, rtnl_fd, &ev) == -1) {
    perror("epoll_ctl");
    exit(1);
  }
  ev.events = EPOLLIN;
  ev.data.fd = nl80211_fd;
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, nl80211_fd, &ev) == -1) {
    perror("epoll_ctl");
    exit(1);
  }

  while (1) {
    nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    if (nfds == -1) {
      if (errno == EINTR) {
        continue;
      }
      perror("epoll_wait");
      exit(EXIT_FAILURE);
    }

    for (n = 0; n < nfds; ++n) {
      if (events[n].data.fd == rtnl_fd) {
        nl_cache_mngr_data_ready(rtnl_mngr);
      } else if (events[n].data.fd == nl80211_fd) {
        nl_recvmsgs_default(event_sock);
      }
    }
  }
}
