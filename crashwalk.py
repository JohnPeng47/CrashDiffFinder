#!/usr/bin/python

from posixpath import pathsep
from typing_extensions import runtime
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
from datetime import datetime
import pickle
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import functools
import time

logging.getLogger("pwnlib").setLevel(logging.WARNING)

class Timer:
    def __init__(self):
        if os.path.exists("perf.log"):
            os.remove("perf.log")
    @staticmethod
    def timer(func):
        """Print the runtime of the decorated function"""
        @functools.wraps(func)
        def wrapper_timer(*args, **kwargs):
            start_time = time.perf_counter()    # 1
            value = func(*args, **kwargs)
            end_time = time.perf_counter()      # 2
            run_time = end_time - start_time    # 3
            print(f"Finished {func.__name__!r} in {run_time:.4f} secs")
            with open("perf.log", "a") as times:
                times.write(str(run_time) + "\n")
            return value
        return wrapper_timer
t = Timer()

# Exceptions
class TimeoutException(Exception):
    pass
class NoCrashException(Exception):
    pass
class CrashwalkError(Exception):
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
            if "exited normally" in line or "exited with" in line:
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
        elif not self.output:
            print("no output")
            raise Exception
        return Exploitable(self.output, self.filename)

class Exploitable:
    def __init__(self, output, crash_file):
        try:
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
            self.assert_correctness()
        except Exception:
            print(f"Crashwalk error, self.output: ")
            for l in self.raw_output:
                print(l)
            raise CrashwalkError

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

    def assert_correctness(self):
        assert self.disassembly
        assert self.get_callstack_raw()
        assert self.classification

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

    def set_linearity(self, linearity):
        self.linearity = linearity

    def set_crash_offset(self, crash_offset):
        self.crash_offset = crash_offset

    def set_crash_bytes(self, crash_bytes):
        self.crash_bytes = crash_bytes

@t.timer
def run_GDBWorker(filepath):
    try:
        print("Checking crash for {}".format(filepath))
        exploitable = GDBJob(executable, filepath).generate_exploitable()
        # why doesn't python complain about explotiables not being declared as global variable
        return exploitable
    except NoCrashException as e:
        print("No crash")

def get_pickle_fname(pickle_path):
    pickle_fname = os.path.normpath(pickle_path)
    if "/" in pickle_fname:
        pickle_fname = pickle_fname.replace('/', "_")
    return pickle_fname

def write_pickle(pickle_path, exploitables):
    if os.path.isdir(pickle_path):
        pickle_path += datetime.now().strftime("%m-%d-%Y_%H_%M_%S")
    with open("{}.pickle".format(pickle_path), "wb") as cw_pickle:
        # only exploitable crashes are going to be serialized
        # exploitables = [e for e in exploitables if e != None and e.exploitable]
        exploitables = [e for e in exploitables if e]
        pickle.dump(exploitables, cw_pickle)

if __name__ == "__main__":
    argParse = argparse.ArgumentParser()
    argParse.add_argument("--executable", help="Path to the executable, if not provided via cmdline, will be read from CRASHWALK_BINARY env variable")
    argParse.add_argument("path", help="Path to the crash file")
    argParse.add_argument("--pickle-name", help="Optionally specify the name of the pickle file")
    argParse.add_argument("--verbose", help="Print output to stdout", action="store_true")

    arguments = argParse.parse_args()

    try:
        executable = arguments.executable if arguments.executable else os.environ["CRASHWALK_BINARY"]
    except KeyError:
        print("Please specify the executable binary via env variables or cmd line arguments")
        sys.exit(-1)
    pickle_name = arguments.pickle_name
    path = arguments.path
    verbose = arguments.verbose if arguments.verbose else False

    GDB_PROCS = multiprocessing.cpu_count()
    crash_files = [path]

    # no recursive search for crash files and all files present are crash files
    if os.path.isdir(path):
        crash_files = glob.glob(os.path.join(path, "*"))
    total_files = len(crash_files)

    # initialize length so each thread can individually update its index without locking
    exploitables = []
    # updates the exit status of the GDB job: 1 for success, 2 for an exception raised
    run_status = [0] * len(crash_files)

    # TODO: fix this
    # try:
    #     # read files previously seen files and skip them
    #     seen_crashes = [s.strip() for s in open(".prev_files.db", "r").readlines()]
    #     crash_files = [crash for crash in crash_files if crash not in seen_crashes]
    #     print("Restarting, using {}, {}/{} files to look through".format(crash_files[0], len(crash_files), total_files))
    # except FileNotFoundError as e:
    #     pass
    # except IndexError:
    #     print("{} already processed in previous run")
    #     sys.exit(-1)

    seen_crashes = open(".prev_files.db", "a")
    pending_futures = []
    try:
        with ThreadPoolExecutor(max_workers=GDB_PROCS) as executor:
            for i, crash in enumerate(crash_files):
                print("Launching job {}".format(i))
                pending_futures.append( executor.submit(run_GDBWorker, crash) )

            # as_completed registers a callback event that gets called for each thread that's current waiting on a exploitable object
            # https://stackoverflow.com/questions/51239251/how-does-concurrent-futures-as-completed-work
            for future in as_completed(pending_futures):
                exploitable = future.result()
                if verbose:
                    exploitable.print_raw()
                exploitables.append(future.result())

    except KeyboardInterrupt:
        if not pickle_name:
            pickle_name = get_pickle_fname(path)
        print("Serializing pickle")
        write_pickle(pickle_name, exploitables)

    if not pickle_name:
        pickle_name = get_pickle_fname(path)
    write_pickle(pickle_name, exploitables)
