#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import termios
import tty
import pty
import time
from subprocess import Popen, STDOUT
from threading import Thread

# https://stackoverflow.com/questions/41542960/run-interactive-bash-with-popen-and-a-dedicated-tty-python
class Process:
    def __init__(self, command):
        self.child_buf = []
        # save original tty setting then set it to raw mode
        self.old_tty = termios.tcgetattr(sys.stdin)
        tty.setraw(sys.stdin.fileno())

        # open pseudo-terminal to interact with subprocess
        master_fd, slave_fd = pty.openpty()
        self.master_fd, self.slave_fd = master_fd, slave_fd

        # for keeping track of the current index in the read buffer in case of partial reads with recvuntil
        self.partial_buf = None
        try:
            self.proc = Popen(command,
                    preexec_fn=os.setsid,
                    stdin=self.slave_fd,
                    stdout=self.slave_fd,
                    stderr=self.slave_fd)
            
            self.proc.stdin = os.fdopen(os.dup(self.slave_fd), 'r+b', 0)
            self.proc.stdout = os.fdopen(os.dup(self.slave_fd), 'r+b', 0)
            self.proc.stderr = os.fdopen(os.dup(self.slave_fd), 'r+b', 0)

            os.close(slave_fd)                    
        finally:
            # restore tty settings back
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_tty)

    def close(self):
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_tty)

    def recvuntil(self, stop):
        partial_stop = 0
        skip_until = None
        if self.last_write:
            skip_until = self.last_write
            self.last_write = None

        # in case the last recv stopped reading partially before it could empty out the entire buffer
        output = bytes() if not self.partial_buf else self.partial_buf
        stop_bytes = stop.strip().encode("utf-8")

        # HACK: since we are reading and writing to the same fd, so
        # the stop string is seen once when it is written to the terminal and read
        # immediately, but we want to read it when GDB writes it to the slave stdin
        while True:
            # try to find the stop within the partial buf without reading more data from fd
            if self.partial_buf:
                try:
                    partial_stop = self.partial_buf.index(stop_bytes) + len(stop_bytes)
                    ret_buf = self.partial_buf[:partial_stop]
                    self.partial_buf = self.partial_buf[partial_stop:]
                    return ret_buf
                except ValueError:
                    pass
            b = os.read(self.master_fd, 10000)
            print("bytes: ", b)
            if skip_until:
                try:
                    b = b[b.index(skip_until) + len(skip_until) - 1:]
                    skip_until = None
                    continue
                # currently don't handle the case where a word is split into two different read streams
                except ValueError:
                    continue
            output += b
            if stop_bytes in b:
                partial_stop = b.index(stop_bytes) + len(stop_bytes)
                self.partial_buf = b[partial_stop:]       
                break
        output_stop = output.index(stop_bytes) + len(stop_bytes)
        return output[:output_stop]

    def write(self, data):
        # HACK: data gets written to the same fd that is read from
        # so we need to clean up our data by start recving after the last word written
        self.last_write = bytes(data.strip(), encoding="utf-8")
        try:
            os.write(self.master_fd, bytes(data.encode("utf-8")))
        except IOError as e:
            print("IOError {}".format(e))

# Utils
def find_last_substring_index(str, sub, sub_index = 0):
    try:
        old_length = sub_index
        sub_index = str[sub_index:].index(sub)
        if sub_index + len(sub) < len(str) - 1:
            val = find_last_substring_index(str[sub_index:], sub, sub_index = sub_index + len(sub))
            print(val)
            return val
        return sub_index + old_length
    except ValueError:
        return 0 if sub_index +  len(sub) < len(str) else sub_index

# Debugging purposes please ignore
if __name__ == "__main__":
    s = "hello__hiofgoeigeig__hellokgnioengieg"
    find_last_substring_index(s, "hello")