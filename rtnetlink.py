import select

import _nl80211
import _rtnetlink

class C:
    def link_change(self, arg):
        print("link_change", arg)
    def addr_change(self, arg):
        permanent = bool(arg['data'].get('flags', 0) & 0x80)
        print("addr_change", arg, "permanent", permanent)
    def wlan_event(self, arg):
        if arg['cmd'] == 'NEW_SCAN_RESULTS' and 'ssids' in arg:
            ssids = set()
            for (ssid, status) in arg['ssids']:
                ssids.add(ssid)
                if status != "no status":
                    print(status, ssid)
            print("ssids:", sorted(ssids))
            return
        if arg['cmd'] == 'NEW_INTERFACE' and arg['ifindex'] > 0:
            wlan_listener.trigger_scan(arg['ifindex'])
        print("wlan_event", arg)

c = C()

rtlistener = _rtnetlink.listener(c)
rtlistener.start()

wlan_listener = _nl80211.listener(c)
wlan_listener.start()

fdmap = {
    rtlistener.fileno(): rtlistener.data_ready,
    wlan_listener.fileno(): wlan_listener.data_ready,
    }

poll_ob = select.epoll()
for fd in fdmap:
    poll_ob.register(fd, select.EPOLLIN)
while True:
    events = poll_ob.poll()
    for (fd, e) in events:
        fdmap[fd]()
