#!/usr/bin/python3

import threading

class StoppableThread(threading.Thread):
    _name = "THREAD"

    def __init__(self, *args, **kwargs):
        super(StoppableThread, self).__init__(*args, **kwargs)
        self.__stop_event = threading.Event()

    def set_name(self, _str):
        self._name = _str

    def free_resources(self):
        raise NotImplementedError(f"[{self._name}] Can not free up resources, must override method")

    def shutdown(self):
        print(f'[{self._name}] Parent requested shutdown')
        self.__stop_event.set()
        print(f'[{self._name}] Resource cleaned up, exiting thread...')

    def must_shutdown(self):
        return (self.__stop_event.is_set())

