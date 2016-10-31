import select

import _rtnetlink

class C:
    def link_change(self, arg):
        print("link_change", arg)
    def addr_change(self, arg):
        print("addr_change", arg)

listener = _rtnetlink.listener(C())
fd = listener.fileno()
listener.start()

poll_ob = select.epoll()
poll_ob.register(fd, select.EPOLLIN)
while True:
    events = poll_ob.poll()
    listener.data_ready()
