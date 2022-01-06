from posixpath import pathsep
from pwn import process, context
import glob
import sys
import argparse
import os
import glob
import re
import hashlib
import threading
import multiprocessing
from time import sleep
import pickle
import traceback
import logging

logging.getLogger("pwnlib").setLevel(logging.WARNING)

# Exceptions
class TimeoutException(Exception):
    pass
class NoCrashException(Exception):
    pass
# TODO: should not have written this as two separate classes
class GDBJob:
    def __init__(self, proc_name, filename, timeout=20):
        START_PARSE = "---START_HERE---"
        END_PARSE = "---END_HERE---"
        self.filename = filename
        self.crashed = True
        self.timedout = False
        exploitable_path = "/mnt/c/Users/pengjohn/Documents/tools/exploit/exploitable/exploitable/exploitable.py"
        if env_exploitable := os.environ.get("EXPLOITABLE_PATH", None):
            print("Using EXPLOITABLE path from environment")
            self.exploitable_path = env_exploitable
        context.log_level = "error"
        gdb = process(["gdb", "--args", proc_name, filename], stdin=process.PTY, stdout=process.PTY, timeout=timeout)
        # PWN complains when string encoding is not explicit
        # Need this or GDB will require user keystroke to display rest of output
        gdb.sendline("set height unlimited".encode("utf-8"))
        gdb.sendline("gef config context False".encode("utf-8"))
        gdb.sendline("r".encode("utf-8"))
        if not os.path.isfile(exploitable_path):
            raise Exception(f"Exploitable not found at {exploitable_path}".encode("utf-8"))
        gdb.sendline(f"source {exploitable_path}".encode("utf-8"))
        gdb.sendline(f"p '{START_PARSE}'".encode("utf-8"))
        gdb.sendline("exploitable -v".encode("utf-8"))
        actions = [
            "frame 2",
            "p *next"
        ]
        # segfaulting address
        gdb.sendline("SegfaultAddy".encode("utf-8"))
        gdb.sendline("p $_siginfo._sifields._sigfault.si_addr".encode("utf-8"))
        self.send(actions, gdb)
        gdb.sendline(f"p '{END_PARSE}'".encode('utf-8'))
        self.output = gdb.recvuntil(f"{END_PARSE}".encode("utf-8")).decode('utf-8').split('\n')
        gdb.close()

        if self.timedout == True:
            return
        # check if process actually crashed
        for line in self.output:
            if "exited normally" in line:
                self.crashed = False

    def send(self, actions, gdb):
        for action in actions:
            gdb.sendline(action.encode("utf-8"))

    def generate_exploitable(self):
        if not self.crashed:
            print("{} did not crash".format(self.filename))
            raise NoCrashException
        elif self.timedout == True:
            print("{} timed out".format(self.filename))
            raise TimeoutException
        return Exploitable(self.output, self.filename)

class Exploitable:
    def __init__(self, output, crash_file):
        START_PARSE = "---START_HERE---"
        self.classification = []
        self.exploitable = False
        self.crash_file = crash_file
        self._output = iter(output)
        self.raw_output = output
        not_start = True
        line = next(self._output, None)
        while line or not_start:
            if f"{START_PARSE}" in line:
                not_start = False
            if "Nearby code:" in line:
                self.disassembly, line = self.parse_until("Stack trace:")
                # Dont need this line since the iterator from the prev parse_until call will consume this line
                # if "Stack trace:" in line:
                self.stack_trace, line = self.parse_until("Faulting frame:")
                self.faulting_frame = line.split(" ")[5]
            if "Description:" in line:
                self.classification, line = self.parse_until("gef")
            if "SegfaultAddy" in line:
                self.segfault = self.parse_segfault()
            line = next(self._output, None)
    
    def parse_segfault(self):
        segfault = next(self._output, None)
        if not segfault:
            raise Exception("Error parsing segfault")
        match = re.search("(0x.*)", segfault)
        if match:
            return match.group(1)

    # hash the first n callstacks
    def get_call_hash(self, n):
        callstack_string = "".join(self.get_callstack()[:n])
        return hashlib.md5(callstack_string.encode("utf-8")).hexdigest()

    def parse_until(self, stop_parse):
        trace = []
        line = next(self._output, None)
        if not line:
            raise Exception("Error parsing stacktrace")
        while line and stop_parse not in line:
            trace.append(line)
            line = next(self._output, None)
        return trace, line

    def get_callstack(self):
        # normalize the spaces for the split call
        #  0 Umbra::BlockMemoryManager<4096>::removeFreeAlloc at 0x7ffff7a6957d in /mnt/c/Users/pengjohn/Documents/umbra/umbra3/bin/linux64/libumbraoptimizer64.so
        callstack = [frame.replace("  ", " ").split(" ")[2] for frame in self.stack_trace]
        return callstack

    def get_callstack_raw(self):
        return self.stack_trace

    # output functions
    def print_raw(self):
        print("Disassembly: ")
        for line in self.disassembly:
            print(line)
        print("CallStack: ")
        for frame in self.get_callstack_raw():
            print(frame)
        for descr in self.classification:
            print(descr)
        print("Segmentation Fault: ", self.segfault)

    def print_results(self):
        for line in self.disassembly:
            print(line)
        for line in self.get_callstack():
            print(line)
        for line in self.stack_trace[:self.callstack_lines]:
            print(line)
        print(self.segfault)

# threading
def run_GDBWorker(filepath, i):
    # references the globally defined PROC_NUM
    global PROC_NUM
    global run_status
    try:
        exploitable = GDBJob(executable, filepath).generate_exploitable()
        exploitable.print_raw()
        # why doesn't python complain about explotiables not being declared as global variable
        exploitables[i] = exploitable
        exploitable.print_raw()
        run_status[i] = 1
        PROC_NUM -= 1
    except Exception as e:
        logging.exception(e)
        # print("Crashed in: ".format(e))
        run_status[i] = 2

if __name__ == "__main__":
    argParse = argparse.ArgumentParser()
    argParse.add_argument("--executable", help="Path to the executable, if not provided via cmdline, will be read from CRASHWALK_BINARY env variable")
    argParse.add_argument("path", help="Path to the crash file, if relative path given, then must be ")

    arguments = argParse.parse_args()
    executable = arguments.executable if arguments.executable else os.environ["CRASHWALK_BINARY"]
    path = arguments.path

    GDB_PROCS = multiprocessing.cpu_count()
    PROC_NUM = 0
    crash_files = [path]
    # no recursive search for crash files and all files present are crash files
    if os.path.isdir(path):
        crash_files = glob.glob(os.path.join(path, "*"))
    total_files = len(crash_files)

    # initialize length so each thread can individually update its index without locking
    exploitables = [None] * len(crash_files)
    # updates the exit status of the GDB job: 1 for success, 2 for an exception raised
    run_status = [0] * len(crash_files)

    try:
        # read files previously seen files and skip them
        seen_crashes = [s.strip() for s in open(".prev_files.db", "r").readlines()]
        crash_files = [crash for crash in crash_files if crash not in seen_crashes]
        print("Restarting, using {}, {}/{} files to look through".format(crash_files[0], len(crash_files), total_files))
    except FileNotFoundError as e:
        pass

    threads = []
    # https://stackoverflow.com/questions/1466000/difference-between-modes-a-a-w-w-and-r-in-built-in-open-function
    # FYI Python uses same file modes as fopen
    # Probably should get rid of the backup options
    seen_crashes = open(".prev_files.db", "a")
    if len(crash_files) > GDB_PROCS:
        for procs in range(GDB_PROCS - 1, len(crash_files), GDB_PROCS):
            for i in range(procs - GDB_PROCS + 1, procs + 1):
                filepath = crash_files[i]
                while PROC_NUM > GDB_PROCS:
                    sleep(1)
                PROC_NUM += 1
                t = threading.Thread(target=run_GDBWorker, args=(filepath, i, ))
                threads.append((t, filepath))
                t.start()       
            # check to make sure all of the threads have been ran. Can think of this as a join for all of the threads in [proc-GDB_PROCS +1: procs +1]
            # Blocks main thread execution until all the threads have written to file
            while len(list(filter(lambda x: x == 1 or x == 2, run_status[procs - GDB_PROCS + 1:procs + 1]))) < GDB_PROCS:
                sleep(1)
            try:
                seen_crashes.write(filepath + '\n')
                print("Persisting ", filepath)
            except IndexError:
                print("End of crash_files reached")
                # probably going to get index error when the GDB_PROCS exceed the of crash_files
                break
    else:
        for i, c in enumerate(crash_files):
            try:
                exploitable = GDBJob(executable, c).generate_exploitable()
                exploitable.print_raw()
                exploitables[i] = exploitable
            except Exception as e:
                logging.exception(e)
                # print("Crashed with exception {}: ".format(e))
    
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

    seen_crashes.close()
