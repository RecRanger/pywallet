from pywallet.conversions import bytes_to_str


class Bdict(dict):
    def __init__(self, *a, **kw):
        super(Bdict, self).__init__(*a, **kw)
        for k, v in self.copy().items():
            try:
                del self[k]
            except KeyError:
                pass
            self[bytes_to_str(k)] = v

    def update(self, *a, **kw):
        other = self.__class__(*a, **kw)
        return super(Bdict, self).update(other)

    def pop(self, k, *a):
        return super(Bdict, self).pop(bytes_to_str(k), *a)

    def get(self, k, default=None):
        return super(Bdict, self).get(bytes_to_str(k), default)

    def __getitem__(self, k):
        return super(Bdict, self).__getitem__(bytes_to_str(k))

    def __setitem__(self, k, v):
        return super(Bdict, self).__setitem__(bytes_to_str(k), v)

    def __contains__(self, k):
        return super(Bdict, self).__contains__(bytes_to_str(k))

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, super(Bdict, self).__repr__())
