import select

import _nl80211
import _rtnetlink

class BasicObserver:

    def __init__(self):
        self.links = {}

    def link_change(self, action, data):
        if action == 'DEL':
            del self.links[data['ifindex']]
        if 'flags' in data:
            data['flags'] = "%08x"%(data['flags'],)
        name = data['name'].decode('latin-1')
        self.links[data['ifindex']] = name
        print("link_change", action, data)
    def addr_change(self, action, data):
        permanent = bool(data.get('flags', 0) & 0x80)
        print("addr_change", action, data, "permanent", permanent)
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

if __name__ == '__main__':
    c = BasicObserver()

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
