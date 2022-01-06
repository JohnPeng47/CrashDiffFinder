# purpose of this is to incrementally make file b the same as a in order to isolate the bytes that
# triggered the crash
import sys
import shutil
import subprocess
from crashwalk import GDBJob, Exploitable, NoCrashException
from callstack import ExploitableCallstack
import ExploitableCallstack
import argparse
import os
import logging
import struct
import math

# disable logging from pwn
logging.getLogger("pwnlib").setLevel(logging.WARNING)

class BinDiff:
    def __init__(self, og_crash, pickle_filename, executable, debug=False):
        self.debug = debug
        if self.debug:
            self.debug_dir = "/tmp/debug"
            try:
                os.mkdir(self.debug_dir)
            except OSError:
                print("Tmp directory already created, skipping")

        self.filename = pickle_filename
        self.og_crash = og_crash
        self.executable = executable
        try:
            exploitable = GDBJob(executable, self.og_crash).generate_exploitable()
            self.og_segfault = exploitable.segfault
        except Exception as e:
            logging.exception(e)

            # print("Crashed with exception {}: ".format(e))

        callstack = ExploitableCallstack(pickle_filename, 1)
        most_popular = callstack.get_most_popular()
        # get list of crashing file names
        crashing_files = [callstack.get_exploitable(i).crash_file for i in most_popular["index"]
            if callstack.get_exploitable(i).segfault != self.og_segfault]

        # get min crash
        def get_diff_sz(crash_file):
            diff_sz = 0
            diff = self.radiff2(self.og_crash, crash_file)
            print("Diff {} for {}".format(diff, crash_file))
            for l in diff:
                a_off, a_bytes, _, b_bytes, b_off = l.split(" ")
                a_bytes = [int(a_bytes[i:i+2], 16) for i in range(0, len(a_bytes)-1, 2)]
                diff_sz += len(a_bytes)
            # Hack to handle the case when the og_file is included in the crashes
            if diff_sz == 0:
                print("OG file found in crash pickle, skipping...")
                return 1000000
            return diff_sz

        for crash in crashing_files:
            print(crash)

        crashing_files.sort(key=get_diff_sz)
        for crash_file in crashing_files:
            print("File: ", crash_file)
            offset, modified_bytes, modified_fname = self.get_crashing_offset(self.og_crash, crash_file)
            self.find_control_width(offset, modified_bytes, modified_fname)

    def radiff2(self, a, b):
        res, err = subprocess.Popen(["radiff2", a, b], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).communicate()
        # remove extra line at the end of the file
        return res.decode('utf-8').split("\n")[:-1]

    # how to handle case when a is bigger (more bytes) than b?
    def get_crashing_offset(self, a, b):
        modified_b = self.filename + ".modified"
        diff = []
        for l in self.radiff2(a,b):
            try:
                a_off, a_bytes, _, b_bytes, b_off = l.split(" ")
                # since we are only concerned with making b crash with the same register values as a
                # only store a's bytes and b's offset
                # print((a_off, a_bytes))
                a_bytes = [int(a_bytes[i:i+2], 16) for i in range(0, len(a_bytes)-1, 2)]
                a_bytes = bytes(a_bytes)
                diff.append((int(b_off, 16), a_bytes))
            except Exception as e:
                logging.exception(e)
        # iteratively replace each byte until the endresult is the same
        shutil.copyfile(b, modified_b)
        tmp_b_handle = open(modified_b, "r+b")
        offset = None
        modified_bytes = None
        for b_off, a_bytes in diff:
            tmp_b_handle.seek(b_off)
            # write back old bytes after GDB call, so we don't make any inadvertent changes to execution trace
            old_bytes = tmp_b_handle.read(len(a_bytes))
            # double seeking required since advance moves the file pointer
            tmp_b_handle.seek(b_off)
            tmp_b_handle.write(a_bytes)
            tmp_b_handle.flush()

            print("writing {} at {}".format(a_bytes, b_off))
            # Run GDB to check segfaulting address
            try:
                segfault_b = GDBJob(self.executable, modified_b).generate_exploitable().segfault
                # tmp_b_handle.write(old_bytes)
            except Exception as e:
                # print("Exception when parsing exploitable, continuing..".format(e))
                logging.exception(e)
                continue
            if segfault_b == self.og_segfault:
                print("Found crash triggering input fileoffset @ {}, segfaulting addr: {}".format(b_off, segfault_b))
                offset = b_off
                modified_bytes = a_bytes
                break
            # b = tmp_b_handle.read((len(a_bytes)))
        tmp_b_handle.close()
        return offset, modified_bytes, modified_b

    def find_control_width(self, offset, mod_bytes, modified_file):
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
            for i in POSSIBLE_DWORD_BYTE_POS:
                byte_i = offset + i
                modified_handle = open(modified_file, "rb+")
                modified_handle.seek(byte_i)
                # read 1 byte from the dword
                mod_byte = modified_handle.read(1)

                mod_byte_int = int.from_bytes(mod_byte, "little")
                plus_one, plus_2, plus_3 =  [bytes([(mod_byte_int + i) % 256]) for i in range(1, 4)]
                # Note:
                # Do a check the range and see if hex bytes all fall within the range of integer digits (48 - 57)

                # Numbers read from a file are also encoded
                # means that for our test case to handle integer representations, we need read the integers byte by byte
                # and then convert them to hex bytes via decoding, rather than using
                # extract individual bytes from the integer representation
                segfaults = []
                inc_index = 0
                for new_bytes in [plus_one, plus_2, plus_3]:
                    # new_bytes_i = bytes([new_bytes >> 8 * i & 0xFF for i in range(bytes_len)])
                    print("writing {}".format(self.bytes_to_str(new_bytes)))
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
                        print("[*] offset: {}, mod_bytes: {}, og_segfault: {}, segfault: {}".format(byte_i, hex(int.from_bytes(new_bytes, "little")), self.og_segfault, segfault))
                    except NoCrashException as e:
                        # shouldnt really happen
                        print("No crash on {} skipping!".format(i))
                        continue

                # check results for a linear relationship
                segfaults = [int(fault.replace("0x", ""), 16) for fault in segfaults]
                if (segfaults[2] - segfaults[1]) == (segfaults[1] - segfaults[0]) and ((segfaults[1] - segfaults[0]) != 0):
                    segfault_delta = segfaults[2] - segfaults[1]
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
        return False

    # add one for hex bytes that wrap around 256
    def add_wrap(self, a, b):
        return (a + b) % 256

    # utils
    def bytes_to_str(self, b, endianess="little"):
        hex_str = ""
        b = b if endianess == "big" else b[::-1]
        for byte in b:
            hex_str += hex(byte).replace("0x","")
        return "0x" + hex_str

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
if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("og_crash", help="The pickled file of Exploitables")
    args.add_argument("pickle", help="The pickled file of Exploitables")
    args.add_argument("--debug", help="DebugMode", action="store_true")
    arguments = args.parse_args()
    debug = arguments.debug

    executable = os.environ["CRASHWALK_BINARY"] if os.environ["CRASHWALK_BINARY"] else None
    pickle_filename = arguments.pickle
    og_crash = arguments.og_crash

    BinDiff(og_crash, pickle_filename, executable, debug=debug)

