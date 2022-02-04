import os
import pickle
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