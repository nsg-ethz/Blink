from sortedcontainers import SortedDict
from python_code.murmur import _murmur3str

class SortedSlidingDic:

    def __init__(self, stime):
        self.flow_dic = {}
        self.ts_dic = SortedDict()

        self.stime = float(self.unified_ts(stime))

    def unified_ts(self, ts):
        return round(ts, 10)

    def update(self, ts):
        ts = self.unified_ts(ts)

        while len(self.ts_dic) > 0 and ts - self.ts_dic.peekitem(0)[0] > self.stime:
            del self.flow_dic[self.ts_dic.peekitem(0)[1]]
            self.ts_dic.popitem(0)

    def add(self, flow, ts):
        ts = self.unified_ts(ts)

        # Remove the previous timestamp for this flow and the new one instead
        self.remove(flow)

        self.flow_dic[flow] = ts

        if ts in self.ts_dic:
            del self.flow_dic[self.ts_dic[ts]]

        self.ts_dic[ts] = flow

        assert len(self.flow_dic) == len(self.ts_dic)

    def remove(self, flow):
        if flow in self.flow_dic:
            ts = self.flow_dic[flow]

            try:
                del self.flow_dic[flow]
                self.ts_dic.pop(ts)
            except KeyError:
                print 'KeyError ', flow, ts

    def __str__(self):
        res = ''
        for k in self.ts_dic:
             res += str("%.10f" % k)+'\t'+str(self.ts_dic[k])+'\n'

        print res
        #return str(self.ts_dic)

if __name__ == "__main__":
    ssd = SortedSlidingDic(10)
    ssd.add('aaaa', 1)
    ssd.add('bbbb', 2)
    ssd.add('cccc', 3)
    ssd.add('dddd', 4)
    ssd.add('eeee', 5)
    ssd.add('bbbb', 6)
    ssd.add('aaaa', 14)
    ssd.update(14)
    ssd.update(23)


    print str(ssd)
    print len(ssd.flow_dic)
