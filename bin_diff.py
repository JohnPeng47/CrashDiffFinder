#!/usr/bin/python

# purpose of this is to incrementally make file b the same as a in order to isolate the bytes that
# triggered the crash
from ast import Str
from inspect import Attribute
import sys
import shutil
import subprocess
from crashwalk import GDBJob, Exploitable, NoCrashException, run_GDBWorker
from callstack import ExploitableCallstack
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import os
import logging
import struct
import math
import glob
import pickle
import re
from multiprocessing import cpu_count
from typing import List
import datetime

# from utils import bytes_to_hex_str, hex_str_to_bytes, add_bytes

import functools
import time

GDB_PROCS = cpu_count()

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

@t.timer
def runGDBJob(filepath):
    try:
        exploitable = GDBJob(executable, filepath).generate_exploitable()
        # why doesn't python complain about explotiables not being declared as global variable
        return exploitable
    except NoCrashException as e:
        print("No crash")

@t.timer
def replaceBytes(parent, modified_parent, diff):
    res = shutil.copyfile(parent, modified_parent)
    print("res: ", res, "modified: ", modified_parent)
    with open(modified_parent, "w+b") as file_handle:
        # TODO:
        # write back old bytes after GDB call, so we don't make any inadvertent changes to execution trace
        # old_bytes = file_handle.read(len(bytes))
        # double seeking required since advance moves the file pointer
        for offset, bytes in diff:
            file_handle.seek(offset)
            print("Writing {} at {}".format(bytes, offset))
            b = file_handle.write(bytes)
            if b != len(bytes):
                return False

        file_handle.flush()
        return True

class GDBExecutor:
    def __init__(self):
        self.t_pool = ThreadPoolExecutor(max_workers=GDB_PROCS)
    
    def run_jobs(self, crashes):
        jobs = []
        for crash in crashes:
            job = self.t_pool.submit( runGDBJob, crash )
            jobs.append(job)
        return jobs

# disable logging from pwn
logging.getLogger("pwnlib").setLevel(logging.WARNING)

# TODO move them to separate utils folder
def bytes_to_hex_str(b: bytes, endianess="little")-> str:
    hex_str = ""
    b = b if endianess == "big" else b[::-1]
    for byte in b:
        hex_str += hex(byte).replace("0x","")
    return "0x" + hex_str

def hex_str_to_bytes(hex_bytes: str) -> bytes:
    byte_str_array = [int(hex_bytes[i:i+2], 16) for i in range(0, len(hex_bytes)-1, 2)]
    return bytes(byte_str_array)

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

class BinDiff:
    def __init__(self, child_crash, parent_crash, executable, debug=False):
        logging.basicConfig(filename='/tmp/bin_diff/{}'.format(child_crash[child_crash.rindex("/")]), level=logging.WARN)
        self.log = []

        self.no_diff = False
        self.debug = debug
        if self.debug:
            self.debug_dir = "/tmp/debug"
            try:
                os.mkdir(self.debug_dir)
            except OSError:
                print("Tmp directory already created, skipping")

        self.parent_crash = parent_crash
        self.child_crash = child_crash
        self.executable = executable
        self.bytes_controlled = []
        self.tmp_dir = "/tmp/modified"

        try:
            os.mkdir("/tmp/modified")
        except Exception:
            pass
        
        # executing gdb jobs to get the segfault address
        self.executor = GDBExecutor()

        # check that parent and child have diff crash sites
        try:
            futures = self.executor.run_jobs([child_crash, parent_crash])
            self.child_sgsev, self.parent_sgsev = futures[0].result().segfault, futures[1].result().segfault
                            
            if not self.child_sgsev or not self.parent_sgsev:
                print("Either the child or the parent did not crash")
                self.no_diff = True
                return
            if self.child_sgsev == self.parent_sgsev:
                print("Child segfault == Parent segfault, skipping {}".format(child_crash))
                self.no_diff = True
                return
        except NoCrashException:
            return
        except Exception as e:
            print("WTF {}".format(e))

        # get diff of child and parent via radiff2
        diff = diff_crash(child_crash, parent_crash)
        # find crashing offset
        offset, modified_bytes, modified_parent = self.get_crashing_offset(parent_crash, diff)

    def get_crash_analysis(self):
        try:
            return self.linearity, self.bytes_controlled, self.crash_offset
        except AttributeError:
            return None, None, None

    def get_crashing_offset(self, parent, diff):
        child_file = self.child_crash[self.child_crash.rindex("/") + 1:]
        t_pool = ThreadPoolExecutor(max_workers=GDB_PROCS)
        pending_futures = []
        modified_parents = {}
        # copy a newly modified file for each line in the diff
        for i, (parent_off, child_bytes) in enumerate(diff):
            print(self.tmp_dir, child_file + "_" + str(i) + ".modified" )
            modified_parent = os.path.join(self.tmp_dir, child_file + str(i) + ".modified")
            modified_parents[modified_parent] = (parent_off, child_bytes)
            pending_futures.append(t_pool.submit( replaceBytes, parent, modified_parent, parent_off, child_bytes))

        for f in as_completed(pending_futures):
            if not f.result():
                print("Print exiting...")
                sys.exit()

        # execute subprocesses to determine which diff lines crashes the input
        finished = False
        for l in modified_parents.keys():
            print(l)
        future_jobs = self.executor.run_jobs(modified_parents.keys())
        for f in future_jobs:
            if finished:
                print('Cancelling..')
                f.cancel()
            res = f.result()
            parent_sgsev = res.segfault
            parent_crash = res.crash_file
            try:
                if parent_sgsev == self.child_sgsev:
                    finished = True
                    print("PARENT CRASH: >>>>> ", res.crash_file)
                    offset = modified_parents[parent_crash][0]
                    modified_bytes = modified_parents[parent_crash][1]
                    print("Found crash triggering input fileoffset @ {}, segfaulting addr: {}, parent crash original: {}"
                        .format(offset, parent_sgsev, parent_crash))
                    break
            except KeyError:
                finished = False
                continue
        
        return offset, modified_bytes, parent_crash

    # OLD
    # get the crashing file offset by flipping parent bytes to child bytes until the parent file gets the same
    # crashing offset as the child
    # def get_crashing_offset(self, parent, diff):
    #     print("crash_file: {} parent: {}".format(self.child_crash, parent))

    #     modified_parent = self.child_crash + ".modified"
    #     # iteratively replace each byte in the parent crash until both parent and child crash with the same segfaulting address
    #     shutil.copyfile(parent, modified_parent)
    #     p_handle = open(modified_parent, "r+b")
    #     offset = None
    #     modified_bytes = None
    #     for parent_off, child_bytes in diff:
    #         p_handle.seek(parent_off)
    #         # write back old bytes after GDB call, so we don't make any inadvertent changes to execution trace
    #         old_bytes = p_handle.read(len(child_bytes))
    #         # double seeking required since advance moves the file pointer
    #         p_handle.seek(parent_off)
    #         p_handle.write(child_bytes)
    #         p_handle.flush()

    #         print("writing {} at {}".format(child_bytes, parent_off))
    #         # Run GDB to check segfaulting address
    #         try:
    #             segfault_parent = GDBJob(self.executable, modified_parent).generate_exploitable().segfault
    #             # tmp_b_handle.write(old_bytes)
    #         except Exception as e:
    #             logging.exception(e)
    #             continue
    #         # TODO: should log this
    #         self.log.append("child_crash: {}, segfault_parent: {}".format(self.child_sgsev, segfault_parent))
    #         if segfault_parent == self.child_sgsev:
    #             print("Found crash triggering input fileoffset @ {}, segfaulting addr: {}, parent crash original: {}"
    #                 .format(parent_off, segfault_parent, self.parent_sgsev))
    #             offset = parent_off
    #             modified_bytes = child_bytes
    #             break
    #     p_handle.close()
    #     return offset, modified_bytes, modified_parent

    def find_control_width(self, offset, mod_bytes, modified_file):
        linearity = False
        # Test 1: subtract/add n bytes to the mod_bytes @ offset, then compare segfaulting addresses
        # to detect if linear relationship dexists
        test_file = "test_file"
        bytes_len = len(mod_bytes)
        # For now we treat all crashing bytes as an integer offset stored in a DWORD
        if bytes_len <= 4:
            # We go through each of the bytes and increment until we find the lsb of the int
            lsb_offset = offset
            smallest_diff = 10000000
            closest_segfaults = []
            POSSIBLE_DWORD_BYTE_POS = range(-3,4)
            bytes_controlled = [None] * 7
            # iterate through each byte and infer the effect of modifying the byte on the final segfaulting address
            for i in POSSIBLE_DWORD_BYTE_POS:
                byte_i = offset + i
                modified_handle = open(modified_file, "rb+")
                modified_handle.seek(byte_i)
                # read 1 byte from the dword
                mod_byte = modified_handle.read(1)

                mod_byte_int = int.from_bytes(mod_byte, "little")
                plus_one, plus_2, plus_3 =  [bytes([(mod_byte_int + i) % 256]) for i in range(1, 4)]

                segfaults = []
                inc_index = 0
                for new_bytes in [plus_one, plus_2, plus_3]:
                    # new_bytes_i = bytes([new_bytes >> 8 * i & 0xFF for i in range(bytes_len)])
                    print("writing {}".format(bytes_to_hex_str(new_bytes)))
                    modified_handle.seek(byte_i)
                    modified_handle.write(new_bytes)
                    modified_handle.flush()

                    if self.debug:
                        debug_file = os.path.join(self.debug_dir, "{}_{}_{}".format(self.filename, i, inc_index))
                        shutil.copy2(modified_file, debug_file)
                        inc_index += 1
                    try:
                        gdb = GDBJob(self.executable, modified_file)
                        # gdb.print_offset(offset)
                        segfault = gdb.generate_exploitable().segfault
                        segfaults.append(segfault)
                        print("[*] offset: {}, mod_bytes: {}, og_segfault: {}, segfault: {}".format(byte_i, hex(int.from_bytes(new_bytes, "little")), self.child_sgsev, segfault))
                    except NoCrashException as e:
                        # shouldnt really happen
                        segfaults.append(9999999)
                        print("No crash on {} skipping!".format(i))
                        continue

                # check results for a linear relationship
                segfaults = [int(fault.replace("0x", ""), 16) for fault in segfaults]
                # check if segfaults resulting from modifying the same byte remains the same ie. there is a linear relationship between that byte and the segfault
                if (segfaults[2] - segfaults[1]) == (segfaults[1] - segfaults[0]) and ((segfaults[1] - segfaults[0]) != 0):
                    linearity = True
                    segfault_delta = abs(segfaults[2] - segfaults[1])
                    if segfault_delta:
                        byte_pos = int(math.log(int(segfault_delta),2) % 7)
                        bytes_controlled[i+3] = byte_pos
                        if segfault_delta < smallest_diff:
                            smallest_diff = segfault_delta
                            lsb_offset = byte_i
                            byte_index = i
                            closest_segfaults = segfaults
                    print("Linear relationship found {} {}, smallest_diff: {}".format(mod_bytes, modified_file, smallest_diff))
                    for f in segfaults:
                        print(f)
                # write the old bytes back to the tmp file
                modified_handle.seek(byte_i)
                modified_handle.write(new_bytes)
                modified_handle.flush()

        print("Controllable bytes: ", bytes_controlled)
        for s in closest_segfaults:
            print(hex(s))

        # Test 2: Random tests
        return linearity, bytes_controlled


# Basic algorithm
# 1. Find the most popular crash site
# 2. Find the least different crash file with a different segfaulting address
# 3. Find the fileoffset that triggers crash by replacing successive byte ranges between the input file diffs
# -> Greedy strategy: to only change bytes that that differ for the current comparison; this decreases the likelihood of
# a false positive in identifying the input file offset for controlling the crash/segfault address (crashing offset)
# -> Non-greedy strategy: replace all the bytes, but this
# 4. When byte range(s) have been identified, then apply control_width_discovery algorithm for finding the control width
# Prior research by CSE Group used a Metasploit style unique byte ranges strategy, where the identified byte ranges were replaced
# with unqiue byte sequences, which allowed for easy correlation between the segfaulting address and the input file offset. However,
# this strategy only works in the case where the input file bytes are directly accessed as a memory address, without any transformation
# In the case where bytes could be transformed before accessed as memory (ie. some basic linear transformation), this strategy will not
# be able to identify the crashing offset, since bytes in the crash could be very different than their representation in the input file
# 5. Repeat with a less optimal crash file (reason for this may be due to complex operations)
def get_afl_queue_dir(crash_filepath):
    crash_name = crash_filepath[crash_filepath.rindex("/") + 1:]
    crash_dir = crash_filepath[:crash_filepath.rindex("/")]
    parent_id = crash_name.split(",")[0]
    queue_dir = os.path.join(crash_dir[:crash_dir.rindex("/")], "queue")

def get_parents(crash_name, queue_dir):
    parent_id = get_parent_id(crash_name)
    parent_fname = glob.glob()

# handle
def get_parent_id(crash_file):
    # delimiters = [":", "_"]
    # print("crashing_file:", crash_file)
    delimiters = [":"]
    try:
        crash_name = crash_file[crash_file.rindex("/"):]
    except IndexError:
        crash_name = crash_file
    except ValueError:
        crash_name = crash_file
    # afl have different path delimiters
    parent_id = re.search("src:([0-9]*)", crash_file).group(1)
    # id:000000 is the seed corpus, so at this point we stop the search
    if parent_id == "000000":
        return None
    for d in delimiters:
        return "id:" + parent_id

def radiff2(a, b):
    res, err = subprocess.Popen(["radiff2", a, b], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).communicate()
    # remove extra line at the end of the file
    return res.decode('utf-8').split("\n")[:-1]

def get_ancestor_crashes(crash_name, queue_dir, ancestor_tree:list):
    parent_id = get_parent_id(crash_name)
    # we have reached the end of the parent tree
    if not parent_id:
        return
    # print("parent_id", parent_id, "crash_name: ", crash_name)
    # queue_dir needs to be manually specified if the crash_file isn't using AFL's canonical crash path
    try:
        parent = glob.glob(os.path.join(queue_dir, parent_id + "*"))[0]
        ancestor_tree.append(parent)
        return get_ancestor_crashes(parent, queue_dir, ancestor_tree)
    except IndexError:
        return

def find_closest_ancestor(ancestors):
    diff_len = 99999999999
    closest_ancestor = ancestors[0]
    for ancestor_crash in ancestors:
        # get bytes from diff
        #TODO: reimplement radiff in python
        diff = diff_crash(crash_file, ancestor_crash)

        if len(diff) < diff_len:
            diff_len = len(diff)
            print("Closest ancestor: ", ancestor_crash, "diff_bytes: ", len(diff))
            closest_ancestor = ancestor_crash
    print("AAClosest ancestor: ", ancestor_crash, "diff_bytes: ", diff_len)
    # start
    return closest_ancestor

def diff_crash(crash_file, ancestor_crash):
    diff = []
    for l in radiff2(crash_file, ancestor_crash):
        try:
            child_off, child_bytes, _, parent_bytes, parent_off = l.split(" ")
            child_bytes = hex_str_to_bytes(child_bytes)
            diff.append((int(parent_off, 16), child_bytes))
        except Exception as e:
            logging.exception(e)
    return diff

if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("crash_file", help="The AFL canonical crash file path ie. the filepath of the crash generated directly by AFL", nargs="?")
    args.add_argument("--queue", help="Directory of the afl queue")
    args.add_argument("--debug", help="DebugMode", action="store_true")
    args.add_argument("--executable", help="The executable for the binary, can be set using the environment variable CRASHWALK_BINARY")
    args.add_argument("--pickle", help="(IMPORTANT: This is the most used mode) A pickled file that holds a list of executables")

    arguments = args.parse_args()
    default_usage = "Usage information: \n" \
            + "With a pickled crashwalk file: bin_diff --pickles_exploitables <pickles_exploitable>\n" \
            + "With a single crash file:      bin_diff <crash_file> \n"

    debug = arguments.debug
    executable = arguments.executable
    crash_file = os.path.abspath(arguments.crash_file) if arguments.crash_file else None
    pickle_exploitables = os.path.abspath(arguments.pickle) if arguments.pickle else None
    queue_dir = arguments.queue

    print(default_usage)
    start = datetime.datetime.now()

    if not executable:
        executable = os.environ["CRASHWALK_BINARY"] if os.environ["CRASHWALK_BINARY"] else None

    # single crash file mode
    if not pickle_exploitables:
        if not os.path.isfile(crash_file):
            print("Crash file does not exist or is a directory")
            sys.exit(-1)

        # find parent queue_file, assuming that crash_file is a AFL canonical crash path
        crash_name = crash_file[crash_file.rindex("/") + 1:]
        crash_dir = crash_file[:crash_file.rindex("/")]
        parent_id = get_parent_id(crash_name)
        queue_dir = queue_dir if queue_dir else os.path.join(crash_dir[:crash_dir.rindex("/")], "queue")
        try:
            parent_file = glob.glob(os.path.join(queue_dir, parent_id + "*"))[0]
        except IndexError:
            print("Parent ID not found, check if queue_dir is specified corectly")
            sys.exit()
        try:
            diff = BinDiff(crash_file, parent_file, executable, debug=debug)
        except Exception:
            pass
        end = datetime.datetime.now()
        print("Total exec time: ", end-start)
        # linearity, affected_bytes, crash_offset = diff.get_crash_analysis()
        # print(linearity, affected_bytes, crash_offset)
        sys.exit()

    # multiple crashes serialized into pickle mode
    new_exploitables = []

    with open(pickle_exploitables, "rb") as pickled:
        exploitables = pickle.load(pickled)
        for e in exploitables:
            crash = os.path.abspath(e.crash_file)
            crash_name = crash[crash.rindex("/") + 1:]
            crash_dir = crash[:crash.rindex("/")]
            # grab the queue src id from crash name
            # ie. id:000136,sig:11,src:000642,time:5534110,op:havoc,rep:4.pickle
            # TODO: what if you have more than 100k files in the queue
            ancestors = []
            queue_dir = queue_dir if queue_dir else os.path.join(crash_dir[:crash_dir.rindex("/")], "queue")
            get_ancestor_crashes(crash_name, queue_dir, ancestors)
            parent = ancestors[0]

            # find ancestor with the smallest diff; the immediate parent is not guranteed to be the smallest diff
            # Actually, maybe we dont want to do this, since the ancestor crashes may not have directly led to our crash
            # find_closest_ancestor()
            try:
                diff = BinDiff(crash, parent, executable, debug=debug)
            except Exception:
                pass
            # linearity, affected_bytes, crash_offset = diff.get_crash_analysis()
            # if not linearity:
            #     e.set_linearity(None)
            #     e.set_crash_bytes(None)
            #     e.set_crash_offset(None)

            # e.set_linearity(linearity)
            # e.set_crash_bytes(affected_bytes)
            # e.set_crash_offset(crash_offset)
            # new_exploitables.append(e)


    with open(pickle_exploitables + ".bin_diff", "wb") as write_pickled:
        write_pickled.write(pickle.dumps(new_exploitables))
