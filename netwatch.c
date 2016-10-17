#include <netlink/cache.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>

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

int main(int argc, char **argv) {
  struct nl_sock *sock;
  struct nl_cache_mngr *mngr;
  struct nl_cache *link_cache;
  struct nl_cache *addr_cache;
  int r;

  sock = nl_socket_alloc();
  if (sock == NULL) {
    fprintf(stderr, "nl_socket_alloc failed\n");
    exit(1);
  }

  r = nl_cache_mngr_alloc(sock, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
  if (r < 0) {
    fprintf(stderr, "nl_cache_mngr_alloc failed %d\n", r);
    exit(1);
  }

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

  nl_cache_foreach(link_cache, e_link, NULL);
  nl_cache_foreach(addr_cache, e_addr, NULL);

  while (1) {
    r = nl_cache_mngr_poll(mngr, 100000);
    if (r < 0) {
      fprintf(stderr, "nl_cache_mngr_poll failed %d\n", r);
      exit(1);
    }
  }
}
