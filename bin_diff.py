#!/usr/bin/python

# purpose of this is to incrementally make file b the same as a in order to isolate the bytes that
# triggered the crash
import sys
import subprocess
from unittest import TextTestResult
from crashwalk import GDBJob, Exploitable, NoCrashException, run_GDBWorker
from concurrent.futures import as_completed
from utils import bytes_to_hex_str, hex_str_to_bytes, add_bytes, hex_str_to_int, serialize_exploitables, CustomThreadPoolExecutor, GDBExecutor, replaceBytes, replaceBytesDiff
from constants import DWORD, QWORD
import argparse
import os
import logging
import math
import glob
import pickle
import re
from multiprocessing import cpu_count
import datetime
from typing import List
import shutil

GDB_PROCS = cpu_count()
# disable logging from pwn
logging.getLogger("pwnlib").setLevel(logging.WARNING)

class CrashedBytes:
    def __init__(self, child_crash, child_sgsev, parent_crash):
        self.child_crash = child_crash
        self.child_sgsev = child_sgsev
        # self.executable = executable => don't need since defined as a global
        self.tmp_dir = "/tmp/modified"
        try:
            os.mkdir("/tmp/modified")
        except Exception:
            pass
        # executing gdb jobs to get the segfault address
        self.executor = GDBExecutor(executable)
        # get diff of child and parent via radiff2
        diff = diff_crash(child_crash, parent_crash)
        if len(diff) > 30:
            print("Skipping too big..")
            # TODO: change this
            raise NoCrashException

        # find crashing offset
        self.offset, self.modified_bytes, self.modified_parent = self.get_crashing_offset(parent_crash, diff)

    def get_crashing_offset(self, parent, diff):
        child_file = self.child_crash[self.child_crash.rindex("/") + 1:]
        t_pool = CustomThreadPoolExecutor(max_workers=GDB_PROCS)
        pending_futures = []
        modified_parents = {}
        # copy a newly modified file for each line in the diff
        for i, (parent_off, child_bytes) in enumerate(diff):
            print(f"{parent_off}: {child_bytes}")
            modified_parent = os.path.join(self.tmp_dir, child_file + str(i) + ".modified")
            modified_parents[modified_parent] = (parent_off, child_bytes)
            partial_diff = diff[:i+1]
            pending_futures.append(t_pool.submit( replaceBytesDiff, parent, modified_parent, partial_diff))

        for f in as_completed(pending_futures):
            if not f.result():
                print("Print exiting...")
                sys.exit()

        offset = None
        # execute subprocesses to determine which diff lines crashes the input
        future_jobs = self.executor.run_jobs(modified_parents.keys())
        offset, modified_bytes, parent_crash = None, None, None
        try:
            for f in future_jobs:
                # Attempt #1:
                # this doesn't work because all futures are iterated for in the beginning, without the chance for one to complete execution
                # if finished:
                #     print('Cancelling..')
                #     t_pool.shutdown(wait=False)
                res = f.result()
                parent_sgsev = res.segfault
                parent_crash = res.crash_file
                if parent_sgsev == self.child_sgsev:
                    print("PARENT CRASH: >>>>> ", res.crash_file)
                    offset = modified_parents[parent_crash][0]
                    modified_bytes = modified_parents[parent_crash][1]
                    print("Found crash triggering input fileoffset @ {}, segfaulting addr: {}, parent crash original: {}"
                        .format(offset, parent_sgsev, parent_crash))
                    raise ValueError
        # Attempt #2: This will execute unlike attempt #1, but will not cancel pending jobs
        # wait=False just allows the function to return earlier rather than waiting for completion, but neither cancels pending jobs
        except ValueError:
            print("Canceling")
            t_pool.shutdown(wait=True, cancel_futures=True)
    
        # should be returning the unmodified parent here instead of parent_crash
        return offset, modified_bytes, parent_crash

# Create files for modification
class PrepFiles:
    def __init__(self, modified_file, new_bytes, offset):
        self.modified_file = modified_file
        self.new_bytes = new_bytes
        self.offset = offset
        self.linearity = False
        self.tmp_dir = "/tmp/modified/linearity"
        # is this thread safe?
        self.f_index = 0
        self.filenames = []
        try:
            os.rmdir("/tmp/modified/linearity")
            os.mkdir("/tmp/modified/linearity")
        except Exception:
            os.mkdir("/tmp/modified/linearity")

    def __enter__(self):
        for b in self.new_bytes:
            # if byte is zero, increment it
            b = b if b != b"\x00" else bytes([int(b) + 1])
            # use offset to mark out unique files
            filename = os.path.join(self.tmp_dir, "_offset:{}_".format(str(self.offset)) + str(self.f_index))
            shutil.copy(self.modified_file, filename)
            print("byte: {}".format(b))
            with open(filename, "rb+") as handle:
                replaceBytes(handle, self.offset, b)
            self.filenames.append(filename)
            self.f_index += 1
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        if exc_type:
            print("Exception occured of type: {} occurred, value: {}, trace: {}".format(exc_type, exc_value, exc_tb))
        # dont bother saving non-linear modified crashes
        if not self.linearity:
            for f in self.filenames:
                os.remove(f)

    def get_linear_crashes(self):
        return glob.glob(os.path.join(self.tmp_dir, "*"))

class BinDiff:
    def __init__(self, child_crash, parent_crash):
        self.executor = GDBExecutor(executable)

        self.child_sgsev, self.parent_sgsev = self._check_segfault(child_crash, parent_crash)
        if not self.parent_sgsev and not self.child_sgsev:
            raise NoCrashException
        
        crashed = CrashedBytes(child_crash, self.child_sgsev, parent_crash)
        offset = crashed.offset
        modified_bytes = crashed.modified_bytes
        modified_parent = crashed.modified_parent
        self.linearity, self.bytes_controlled = self._find_control_width(offset, modified_bytes, modified_parent)

    def _dword_byte_pos(self, delta):
        return int(math.log(delta,2))

    def _check_segfault(self, child_crash, parent_crash):
        # check that parent and child have diff crash sites
        try:
            futures = self.executor.run_jobs([child_crash, parent_crash], ordered=True)
            child_sgsev = next(futures).segfault
            parent_sgsev = next(futures).segfault
            # child_sgsev, parent_sgsev = futures[0].result().segfault, futures[1].result().segfault
        except AttributeError:
            raise NoCrashException("Check segfault crashed")
        if not child_sgsev or not parent_sgsev:
            print("Either the child or the parent did not crash")
            return None, None
        if child_sgsev == parent_sgsev:
            print("Child segfault == Parent segfault, skipping {}".format(child_crash))
            return None, None
        return child_sgsev, parent_sgsev

    def _is_linear(self, segfaults: List[int]):
        linearity = False
        byte_pos = None

        segfaults = map(hex_str_to_int, segfaults)
        segfaults = list(segfaults)

        # check if segfaults resulting from modifying the same byte remains the same ie. there is a linear relationship between that byte and the segfault
        if (segfaults[2] - segfaults[1]) == (segfaults[1] - segfaults[0]) and ((segfaults[1] - segfaults[0]) != 0):
            linearity = True
            segfault_delta = abs(segfaults[2] - segfaults[1])
            if segfault_delta:
                byte_pos = self._dword_byte_pos(segfault_delta)
                # bytes_controlled[i+3] = byte_pos
                # if segfault_delta < smallest_diff:
                #     smallest_diff = segfault_delta
                #     closest_segfaults = segfaults
            print("Linear relationship found: {}", segfaults)
        return linearity, byte_pos

    def _get_byte_n_offset(self, mod_bytes, offset, modified_file, struct_size=DWORD):
        possible_bytes = bytes()
        off_start = offset - struct_size + 1
        off_end = offset + len(mod_bytes)
        with open(modified_file, "rb") as handle:
            handle.seek(off_start)
            possible_bytes += handle.read(struct_size - 1)
            possible_bytes += mod_bytes
            handle.seek(off_end)
            possible_bytes += handle.read(struct_size - 1)
        print(type(possible_bytes))
        return zip(possible_bytes, range(off_start, off_end + struct_size))

    def _find_control_width(self, mod_offset, mod_bytes, modified_file):
        linear_relationship = False
        bytes_controlled = [None] * (len(mod_bytes) + 2 * (DWORD - 1))
        # Test 1: subtract/add n bytes to the mod_bytes @ offset, then compare segfaulting addresses
        # to detect if linear relationship exists
        # For now we treat all crashing bytes as an integer offset stored in a DWORD
        if len(mod_bytes) <= 4:
            # get the bytes that come before/after the DWORD/QWORD in memory
            bytes_n_offsets = self._get_byte_n_offset(mod_bytes, mod_offset, modified_file, struct_size=DWORD)

            # Apparently iterating over bytes in Python will yield ints
            for byte, offset in bytes_n_offsets:
                assert(type(byte) == int)
                # Note: add_bytes adds a wraparound behaviour that is not currently accounted for in the linearity calculation
                inc_bytes =  [add_bytes(byte, i) for i in range(0, 3)]
                inc_bytes =  bytes(inc_bytes)
                with PrepFiles(modified_file, inc_bytes, offset) as files:
                    exploitables = self.executor.run_jobs(files.filenames, ordered=True)
                    # if any one of the files do not crash, just skip this batch of files
                    try:
                        segfaults = [e.segfault for e in exploitables]
                        print(segfaults)
                    except Exception as e:
                        print(e)
                        continue
                # check if segfaults resulting from modifying the same byte remains the same ie. there is a linear relationship between that byte and the segfault
                linearity, byte_pos = self._is_linear(segfaults)
                if linearity:
                    # which bytes in the segfault are controllable
                    bytes_controlled[offset - mod_offset + DWORD - 1] = byte_pos
                linear_relationship = linearity if not linear_relationship else True
        
            print("bytes_controlled: ", bytes_controlled)
        # Test 2: Random tests
        return linear_relationship, bytes_controlled

    def get_crash_analysis(self):
        try:
            return self.linearity, self.bytes_controlled
        except AttributeError:
            return None, None, None

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

# TODO: USE THIS FUNCTION
def get_afl_queue_dir(crash_filepath):
    crash_name = crash_filepath[crash_filepath.rindex("/") + 1:]
    crash_dir = crash_filepath[:crash_filepath.rindex("/")]
    parent_id = crash_name.split(",")[0]
    queue_dir = os.path.join(crash_dir[:crash_dir.rindex("/")], "queue")

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
    # queue_dir needs to bemanually specified if the crash_file isn't using AFL's canonical crash path
    try:
        parent = glob.glob(os.path.join(queue_dir, parent_id + "*"))[0]
        ancestor_tree.append(parent)
        return get_ancestor_crashes(parent, queue_dir, ancestor_tree)
    except IndexError:
        print("No ancestors found, check that queue directory is correct: ", ancestor_tree)
        return

def find_closest_ancestor(crash_file, ancestors):
    print(crash_file)
    diff_len = 99999999999
    closest_ancestor = ancestors[0]
    for ancestor_crash in ancestors:
        # get bytes from diff
        #TODO: reimplement radiff in python
        diff = diff_crash(crash_file, ancestor_crash)
        print(len(diff), ancestor_crash)
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
    args.add_argument("--queue", help="Directory of the afl queue", required=True)
    args.add_argument("--debug", help="DebugMode", action="store_true")
    args.add_argument("--executable", help="The executable for the binary, can be set using the environment variable CRASHWALK_BINARY")
    args.add_argument("--pickle", help="(IMPORTANT: This is the most used mode) A pickled file that holds a list of executables")

    arguments = args.parse_args()
    default_usage = "Usage information: \n" \
            + "With a pickled crashwalk file: bin_diff --pickle <pickles_exploitable>\n" \
            + "With a single crash file:      bin_diff <crash_file> \n"

    debug = arguments.debug
    executable = arguments.executable
    crash_file = os.path.abspath(arguments.crash_file) if arguments.crash_file else None
    pickle_exploitables = os.path.abspath(arguments.pickle) if arguments.pickle else None
    queue_dir = os.path.abspath(arguments.queue) if arguments.queue else None

    print(default_usage)
    start = datetime.datetime.now()

    if not executable:
        executable = os.environ["CRASHWALK_BINARY"] if os.environ["CRASHWALK_BINARY"] else None

    print("EXECUTABLE: ", executable)
    # single crash file mode
    if not pickle_exploitables:
        if not os.path.isfile(crash_file):
            print("Crash file {} does not exist or is a directory".format(crash_file))
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

        diff = BinDiff(crash_file, parent_file)

        # linearity, affected_bytes, crash_offset = diff.get_crash_analysis()
        # print(linearity, affected_bytes, crash_offset)

    # multiple crashes serialized into pickle mode
    else:
        new_exploitables = []
        with open(pickle_exploitables, "rb") as pickled:
            exploitables = pickle.load(pickled)
            for e in exploitables:
                try:
                    crash_file = os.path.abspath(e.crash_file)
                    crash_name = crash_file[crash_file.rindex("/") + 1:]
                    crash_dir = crash_file[:crash_file.rindex("/")]
                    print("crash_file", crash_file)
                    # grab the queue src id from crash name
                    # ie. id:000136,sig:11,src:000642,time:5534110,op:havoc,rep:4.pickle
                    # TODO: what if you have more than 100k files in the queue
                    ancestors = []
                    queue_dir = queue_dir if queue_dir else os.path.join(crash_dir[:crash_dir.rindex("/")], "queue")

                    get_ancestor_crashes(crash_name, queue_dir, ancestors)
                    parent = ancestors[0]

                    # find ancestor with the smallest diff; the immediate parent is not guranteed to be the smallest diff
                    # Actually, maybe we dont want to do this, since the ancestor crashes may not have directly led to our crash
                    # find_closest_ancestor(crash_file, ancestors)
                    # try:
                    diff = BinDiff(crash_file, parent)
                    # except Exception as e:
                    #     print("{}".format(e))
                    #     pass

                    linearity, affected_bytes = diff.get_crash_analysis()
                    if not linearity:
                        e.set_linearity(None)
                        e.set_crash_bytes(None)

                    e.set_linearity(linearity)
                    e.set_crash_bytes(affected_bytes)
                    new_exploitables.append(e)
                except NoCrashException:
                    continue
    end = datetime.datetime.now()
    print("time: ", end - start)
    # with open(pickle_exploitables + ".bin_diff", "wb") as write_pickled:
    #     write_pickled.write(pickle.dumps(new_exploitables))
