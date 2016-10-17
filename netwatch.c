#include <netlink/cache.h>


static void cb(struct nl_cache * cache, struct nl_object *ob, int dunno, void *data) {
	printf("cb called with dunno %d\n", dunno);
}

int main(int argc, char **argv) {
  struct nl_cache_mngr *mngr;
  struct nl_cache *cache;
  int r;

  // Allocate a new cache manager for RTNETLINK and automatically

  // provide the caches added to the manager.

  r = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
  if (r < 0) {
	  fprintf(stderr, "nl_cache_mngr_alloc failed %d\n", r);
	  exit(1);
  }

  r = nl_cache_mngr_add(mngr, "route/link", cb, NULL, &cache);
  if (r < 0) {
	  fprintf(stderr, "nl_cache_mngr_add failed %d\n", r);
	  exit(1);
  }
}
