import select

import _nl80211
import _rtnetlink

class C:
    def link_change(self, arg):
        print("link_change", arg)
    def addr_change(self, arg):
        print("addr_change", arg)

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
