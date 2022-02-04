import argparse
from collections import defaultdict, OrderedDict
from os import lseek
from crashwalk import Exploitable
import pickle
import sys

# TODO: need to differentiate between location of crash within fauting frame; this is going to effect comparison of stack traces
# ^^^ THIS IS ACTUALLY KINDA IMPORTANT
# TODO: map frame to a source line
class ExploitableCallstack:
    def __init__(self, filename, display_frames):
        self.total_exploitables = 0
        self.callstacks = defaultdict(dict)
        self.exploitables = []
        display_frames = int(display_frames) if display_frames else 3
        with open(filename, "rb") as pickled:
            pickled_output = pickle.load(pickled)

        print(len(pickled_output))
        for e in pickled_output:
            print(e.segfault)
        #     # if e and e.exploitable:
        #     # really dependent on this script to minimize false negatives
        #     index = len(self.exploitables)
        #     callstack_hash = e.get_call_hash(display_frames)
        #     if not self.callstacks.get(callstack_hash):
        #         self.callstacks[callstack_hash]["index"] = []
        #         self.callstacks[callstack_hash]["callstack"] = e.get_callstack()[:display_frames]
        #     self.callstacks[callstack_hash]["index"].append(index)
        #     self.exploitables.append(e)
        #     self.total_exploitables += 1

        # # callstacks.items() returns a 2-tuple instead
        # self.callstacks = sorted(self.callstacks.values(), key=lambda x: len(x["index"]), reverse=True)
    
    def get_most_popular(self):
        return self.callstacks[0]

    def get_exploitable(self, i):
        return self.exploitables[i]

    def pprint_crashing_callstacks(self):
        # take the three most popular crashing sites
        accounted_for = 0
        for stack in self.callstacks[:3]:
            print("Same Crash Sites: {}/{}".format(len(stack["index"]), self.total_exploitables))
            print("Callstack :")
            for frame in stack["callstack"]:
                print(frame)
            accounted_for += len(stack["index"])
        print("{} in the top 3 crash sites, which is {}% of the total crashes".format(accounted_for, int(accounted_for/self.total_exploitables * 100)))

if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("--search")
    args.add_argument("--frames", help="Number of frames in the callstack to compare", default=None)
    args.add_argument("--out", help="Stores in an output file")
    args.add_argument("--filter", metavar="KEY=VALUE", nargs="+", help="""
        Accepts key-value pairs for filtering output. The following are supported: 
        """)
    args.add_argument("pickle", help="The pickled file of Exploitables")

    arguments = args.parse_args()
    search = arguments.search
    frames = arguments.frames
    pickle_filename = arguments.pickle
    filter = arguments.filter

    callstack = ExploitableCallstack(pickle_filename, frames)
    # callstack.pprint_crashing_callstacks()
