# purpose of this is to incrementally make file b the same as a in order to isolate the bytes that
# triggered the crash
from ast import Str
from inspect import Attribute
import sys
import shutil
import subprocess
from crashwalk import GDBJob, Exploitable, NoCrashException
from callstack import ExploitableCallstack
import argparse
import os
import logging
import struct
import math
import glob
import pickle
# from utils import bytes_to_hex_str, hex_str_to_bytes, add_bytes

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
        try:
            exploitable = GDBJob(executable, self.child_crash).generate_exploitable()
            self.child_sgsev = exploitable.segfault
            exploitable = GDBJob(executable, self.parent_crash).generate_exploitable()
            self.parent_sgsev = exploitable.segfault
            if not self.child_sgsev or not self.parent_sgsev:
                print("Either the child or the parent did not crash")
                self.no_diff = True
                return 
            if self.child_sgsev == self.parent_sgsev:
                print("Child segfault == Parent segfault, skipping {}".format(child_crash))
                self.no_diff = True
                return
        except Exception as e:
            logging.exception(e)
        
        # get bytes from diff
        diff = []
        for l in self.radiff2(self.child_crash, self.parent_crash):
            try:
                child_off, child_bytes, _, parent_bytes, parent_off = l.split(" ")
                child_bytes = hex_str_to_bytes(child_bytes)
                diff.append((int(parent_off, 16), child_bytes))
            except Exception as e:
                logging.exception(e)

        if len(diff) > 27:
            print("{} diff too big, skipping {}".format(len(diff), child_crash))
            self.no_diff = True
            return
        offset, modified_bytes, modified_fname = self.get_crashing_offset(self.parent_crash, diff)
        if not modified_bytes:
            print("Something wrong with: {}".format(self.child_crash))
            for l in self.log:
                logging.debug(l)
            self.no_diff = True
            return
        if len(modified_bytes) > 12:
            print("13 bytes or more")
            self.no_diff = True
            return
        elif len(modified_bytes) <= 4:
            print("4 bytes under")
            self.linearity, self.bytes_controlled = self.find_control_width(offset, modified_bytes, modified_fname)
            self.crash_offset = offset
        elif len(modified_bytes) >= 5 and len(modified_bytes) < 12:
            print("in between")
            self.no_diff = True
            return
        
    def get_crash_analysis(self):
        try:
            return self.linearity, self.bytes_controlled, self.crash_offset
        except AttributeError:
            return None, None, None

    def radiff2(self, a, b):
        res, err = subprocess.Popen(["radiff2", a, b], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).communicate()
        # remove extra line at the end of the file
        return res.decode('utf-8').split("\n")[:-1]

    # get the crashing file offset by flipping parent bytes to child bytes until the parent file gets the same
    # crashing offset as the child
    def get_crashing_offset(self, parent, diff):
        print("crash_file: {} parent: {}".format(self.child_crash, parent))
        modified_parent = self.child_crash + ".modified"        
        # iteratively replace each byte in the parent crash until both parent and child crash with the same segfaulting address
        shutil.copyfile(parent, modified_parent)
        p_handle = open(modified_parent, "r+b")
        offset = None
        modified_bytes = None
        for parent_off, child_bytes in diff:
            p_handle.seek(parent_off)
            # write back old bytes after GDB call, so we don't make any inadvertent changes to execution trace
            old_bytes = p_handle.read(len(child_bytes))
            # double seeking required since advance moves the file pointer
            p_handle.seek(parent_off)
            p_handle.write(child_bytes)
            p_handle.flush()

            print("writing {} at {}".format(child_bytes, parent_off))
            # Run GDB to check segfaulting address
            try:
                segfault_parent = GDBJob(self.executable, modified_parent).generate_exploitable().segfault
                # tmp_b_handle.write(old_bytes)
            except Exception as e:
                logging.exception(e)
                continue
            # TODO: should log this 
            self.log.append("child_crash: {}, segfault_parent: {}".format(self.child_sgsev, segfault_parent))
            if segfault_parent == self.child_sgsev:
                print("Found crash triggering input fileoffset @ {}, segfaulting addr: {}, parent crash original: {}"
                    .format(parent_off, segfault_parent, self.parent_sgsev))
                offset = parent_off
                modified_bytes = child_bytes
                break
        p_handle.close()
        return offset, modified_bytes, modified_parent

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

def get_parent_id(crash_name):
    # afl have different path delimiters
    delimiters = [":", "_"]
    parent_id = crash_name.split(",")[2]
    for d in delimiters:
        try:
            return "id" + d + parent_id[parent_id.index(d)+1:]
        except IndexError:
            continue
        except ValueError:
            continue

if __name__ == "__main__":    
    args = argparse.ArgumentParser()
    args.add_argument("crash_file", help="The AFL canonical crash file path ie. the filepath of the crash generated directly by AFL", nargs="?")
    args.add_argument("--queue_dir", help="Directory of the afl queue")
    args.add_argument("--debug", help="DebugMode", action="store_true")
    args.add_argument("--executable", help="The executable for the binary, can be set using the environment variable CRASHWALK_BINARY")
    args.add_argument("--pickle_exploitables", help="A pickled file that holds a list of executables")

    arguments = args.parse_args()
    debug = arguments.debug
    executable = arguments.executable
    crash_file = arguments.crash_file
    pickle_exploitables = arguments.pickle_exploitables
    queue_dir = arguments.queue_dir

    if not executable:
        executable = os.environ["CRASHWALK_BINARY"] if os.environ["CRASHWALK_BINARY"] else None

    # single crash file mode
    if not pickle_exploitables:
        if not os.path.isfile(crash_file):
            print("Crash file does not exist or is a directoryr")
            sys.exit(-1)
        if not os.path.isabs(crash_file):
            print("Absolute path is required")
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

        diff = BinDiff(crash_file, parent_file, executable, debug=debug)
        linearity, affected_bytes, crash_offset = diff.get_crash_analysis()
        print(linearity, affected_bytes, crash_offset)
        sys.exit()

    # multiple crashes serialized into pickle mode
    new_exploitables = []
    try:
        with open(pickle_exploitables, "rb") as pickled:
            exploitables = pickle.load(pickled)
            for e in exploitables:
                crash_file = e.crash_file
                crash_name = crash_file[crash_file.rindex("/") + 1:]
                crash_dir = crash_file[:crash_file.rindex("/")]
                # grab the queue src id from crash name
                # ie. id:000136,sig:11,src:000642,time:5534110,op:havoc,rep:4.pickle
                # TODO: what if you have more than 100k files in the queue
                parent_id = get_parent_id(crash_name)
                # queue_dir needs to be manually specified if the crash_file isn't using AFL's canonical crash path
                queue_dir = queue_dir if queue_dir else os.path.join(crash_dir[:crash_dir.rindex("/")], "queue")
                try:
                    parent_file = glob.glob(os.path.join(queue_dir, parent_id + "*"))[0]
                except IndexError:
                    print("Parent ID not found, check if queue_dir is specified correctly")
                    sys.exit()
                diff = BinDiff(crash_file, parent_file, executable, debug=debug)
                linearity, affected_bytes, crash_offset = diff.get_crash_analysis()
                if not linearity:
                    e.set_linearity(None)
                    e.set_crash_bytes(None)
                    e.set_crash_offset(None)

                e.set_linearity(linearity)
                e.set_crash_bytes(affected_bytes)
                e.set_crash_offset(crash_offset)
                new_exploitables.append(e)

    except KeyboardInterrupt:
        with open(pickle_exploitables + ".bin_diff", "wb") as write_pickled:
            write_pickled.write(pickle.dumps(new_exploitables))    

    with open(pickle_exploitables + ".bin_diff", "wb") as write_pickled:
        write_pickled.write(pickle.dumps(new_exploitables))    
