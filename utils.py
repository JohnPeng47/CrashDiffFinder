import os
import pickle
from concurrent.futures import ThreadPoolExecutor
import queue
import functools
import time
import shutil
from multiprocessing import cpu_count
from crashwalk import GDBJob, NoCrashException

# utils
def bytes_to_hex_str(b: bytes, endianess="little")-> str:
    hex_str = ""
    b = b if endianess == "big" else b[::-1]
    for byte in b:
        hex_str += hex(byte).replace("0x","")
    return "0x" + hex_str

def hex_str_to_bytes(hex_bytes: str) -> bytes:
    byte_str_array = [int(hex_bytes[i:i+2], 16) for i in range(0, len(hex_bytes)-1, 2)]
    return bytes(byte_str_array)

def hex_str_to_int(hex_bytes: str) -> int:
    return int(hex_bytes.replace("0x", ""), 16)


def add_bytes(a:int, b:int) -> int:
    return (a + b) % 256

def serialize_exploitables(path, exploitables):
    pickle_fname = os.path.normpath(path)
    if "/" in path:
        # Note: Python trick
        # Find reverse index
        # pickle_fname = path[len(path) - path[::-1].index('/'):]
        pickle_fname = pickle_fname.replace('/', "_")
        print("Pickled filename: {}".format(pickle_fname))
    with open("{}.pickle".format(pickle_fname), "wb") as cw_pickle:
        # only exploitable crashes are going to be serialized
        # exploitables = [e for e in exploitables if e != None and e.exploitable]
        exploitables = [e for e in exploitables if e]
        pickle.dump(exploitables, cw_pickle)

# multithread stuff
GDB_PROCS = cpu_count()
class CustomThreadPoolExecutor(ThreadPoolExecutor):
    def shutdown(self, wait=True, *, cancel_futures=False):
        with self._shutdown_lock:
            self._shutdown = True
            if cancel_futures:
                # Drain all work items from the queue, and then cancel their
                # associated futures.
                while True:
                    try:
                        work_item = self._work_queue.get_nowait()
                    except queue.Empty:
                        break
                    if work_item is not None:
                        work_item.future.cancel()

            # Send a wake-up to prevent threads calling
            # _work_queue.get(block=True) from permanently blocking.
            self._work_queue.put(None)
        if wait:
            for t in self._threads:
                t.join()

# class UtilsDecorator:
#     def __init__(self):
#         self.decorators = [
#             Timer,
            
#         ]

class Timer:
    def __init__(self):
        if os.path.exists("perf.log"):
            os.remove("perf.log")

    def wrap(self, func):
        self.timer(func)

    @staticmethod
    def timer(func):
        """Print the runtime of the decorated function"""
        @functools.wraps(func)
        def wrapper_timer(*args, **kwargs):
            start_time = time.perf_counter()    # 1
            value = func(*args, **kwargs)
            end_time = time.perf_counter()      # 2
            run_time = end_time - start_time    # 3
            with open("perf.log", "a") as times:
                times.write(str(run_time) + "\n")
            return value
        return wrapper_timer
    
t = Timer()


# Function overloading python?
@t.timer
def replaceBytesDiff(parent, modified_parent, diff):
    res = shutil.copyfile(parent, modified_parent)
    with open(modified_parent, "r+b") as file_handle:
        # TODO:
        # write back old bytes after GDB call, so we don't make any inadvertent changes to execution trace
        # old_bytes = file_handle.read(len(bytes))
        # double seeking required since advance moves the file pointer
        for offset, bytes in diff:
            file_handle.seek(offset)
            # print("Writing {} at {} @ file: {}".format(bytes, offset, modified_parent))
            b = file_handle.write(bytes)
            if b != len(bytes):
                return False
            file_handle.flush()
        return True

def replaceBytes(file_handle, offset, b):
    if type(b) != bytes:
        b = bytes([b])
    # TODO:
    # write back old bytes after GDB call, so we don't make any inadvertent changes to execution trace
    # old_bytes = file_handle.read(len(bytes))
    # double seeking required since advance moves the file pointer
    file_handle.seek(offset)
    # print("Writing {} at {} @ file: {}".format(bytes, offset, modified_parent))
    written = file_handle.write(b)
    if written != len(b):
        return False
    file_handle.flush()
    return True

class GDBExecutor:
    def __init__(self, executable):
        self.t_pool = CustomThreadPoolExecutor(max_workers=GDB_PROCS)
        self.executable = executable
        self.inc_me = 0

    def run_jobs(self, crashes, ordered=False):
        if not ordered:
            jobs = []
            for crash in crashes:
                job = self.t_pool.submit(self.runGDBJob, crash)
                jobs.append(job)
            return jobs
        # map returns ordered results (not promises)
        else:
            jobs = self.t_pool.map( self.runGDBJob, crashes) 
            return jobs

    @t.timer
    def runGDBJob(self, filepath):
        try:
            # print(f"running {filepath}")
            exploitable = GDBJob(self.executable, filepath).generate_exploitable()
            # why doesn't python complain about explotiables not being declared as global variable
            return exploitable
        except NoCrashException:
            print(f"No crash {filepath}")
            return None
            
if __name__ == "__main__":
    pass