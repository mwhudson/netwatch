import select

import _rtnetlink

fd = _rtnetlink.start_listening()

poll_ob = select.epoll()
poll_ob.register(fd, select.EPOLLIN)
while True:
    events = poll_ob.poll()
    _rtnetlink.data_ready()