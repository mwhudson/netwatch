import select

import _nl80211
import _rtnetlink

class BasicObserver:

    def __init__(self):
        self.links = {}

    def link_change(self, arg):
        d = arg['data']
        if arg['action'] == 'DEL':
            del self.links[d['ifindex']]
        if 'flags' in d:
            d['flags'] = "%08x"%(d['flags'],)
        name = d['name'].decode('latin-1')
        self.links[d['ifindex']] = name
        #print("link_change", arg, typ)
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

c = BasicObserver()

rtlistener = _rtnetlink.listener(c)
rtlistener.start()

print(c.links)

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
