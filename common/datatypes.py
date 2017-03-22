class BaseStore:

    def __init__(self):
        self.storage = {}

    def __setitem__(self, key, value):
        self.storage[key] = value

    def __getitem__(self, key):
        return self.storage[key]

    def __iter__(self):
        return iter(self.storage)

    def __len__(self):
        return len(self.storage)

    def __contains__(self, key):
        return key in self.storage

    def get(self, key, default=None):
        if key in self.storage:
            return self.storage[key]
        else:
            return default

    def reset(self):
        del self.storage
        self.storage = {}
