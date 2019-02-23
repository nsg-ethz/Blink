from threading import Timer

class RepeatingTimer(object):

    def __init__(self, interval_init, interval_after, f, *args, **kwargs):
        self.interval = interval_init
        self.interval_after = interval_after
        self.f = f
        self.args = args
        self.kwargs = kwargs
        self.stopped = False
        self.running = False

        self.timer = None

    def callback(self):
        self.running = True
        self.f(*self.args, **self.kwargs)
        self.running = False
        if not self.stopped:
            self.start()

    def cancel(self):
        self.timer.cancel()
        self.stopped = True

    def start(self):
        self.timer = Timer(self.interval, self.callback)
        self.interval = self.interval_after
        self.stopped = False
        self.timer.start()
