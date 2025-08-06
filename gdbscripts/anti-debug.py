# ~/.gdbinit or in gdb: source <file>

import gdb, re

def _get_exe_ranges():
    """Return a list of (start, end) tuples for RX segments of the main executable."""
    ranges = []
    for objfile in gdb.objfiles():
        if objfile.filename == gdb.current_progspace().filename:
            for sect in objfile.sections:
                if sect.prots & gdb.SECTION_PROT_RX:
                    ranges.append((sect.addr, sect.addr + sect.size))
    return ranges

def _search_bytes(byte_seq, max_hits=100):
    """Search all exe RX segments for byte_seq, return list of addresses."""
    hits = []
    inferior = gdb.selected_inferior()
    for start, end in _get_exe_ranges():
        addr = start
        while addr < end and len(hits) < max_hits:
            try:
                # search at most 0x1000 bytes at a time
                chunk = inferior.read_memory(addr, min(0x1000, end - addr)).tobytes()
            except gdb.MemoryError:
                addr += 0x1000
                continue
            for m in re.finditer(re.escape(byte_seq), chunk):
                hits.append(addr + m.start())
                if len(hits) >= max_hits:
                    break
            addr += len(chunk)
    return hits

class FindPtrace(gdb.Command):
    """find_ptrace — locate ptrace(PTRACE_TRACEME) calls"""
    def __init__(self):
        super(FindPtrace, self).__init__("find_ptrace", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        # x86_64: call ptrace in PLT is 0xE8 <rel32>
        sym = gdb.lookup_global_symbol('ptrace')
        if not sym:
            print("ptrace symbol not found!")
            return
        plt_addr = sym.value().address
        # find relative calls: E8 <disp32>
        hits = _search_bytes(b'\xE8' + (plt_addr - 0) .to_bytes(4, 'little'))
        for addr in hits:
            print(f"ptrace call @ 0x{addr:x}")

class FindGetppid(gdb.Command):
    """find_getppid — locate getppid() syscall usage"""
    def __init__(self):
        super(FindGetppid, self).__init__("find_getppid", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        # on x86_64 getppid in PLT is a call as above
        sym = gdb.lookup_global_symbol('getppid')
        if not sym:
            print("getppid symbol not found!")
            return
        addr = sym.value().address
        hits = _search_bytes(b'\xE8' + (addr - 0).to_bytes(4, 'little'))
        for a in hits:
            print(f"getppid call @ 0x{a:x}")

class FindSignal(gdb.Command):
    """find_signal — locate signal()/raise(SIGTRAP) pairs"""
    def __init__(self):
        super(FindSignal, self).__init__("find_signal", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        # look for 'int3' instruction bytes 0xCC
        hits = _search_bytes(b'\xCC')
        for a in hits:
            print(f"trap int3 @ 0x{a:x}")

class FindForkPtrace(gdb.Command):
    """find_fork_ptrace — detect self-fork+ptrace anti-debug"""
    def __init__(self):
        super(FindForkPtrace, self).__init__("find_fork_ptrace", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        # look for fork(0x...) then ptrace attach
        hits = _search_bytes(b'\xE8')
        print("Fork/ptrace suspects (inspect context around each):")
        for a in hits:
            print(f"possible call @ 0x{a:x}")

class FindInt3(gdb.Command):
    """find_int3 — locate 0xCC interrupts (debug traps)"""
    def __init__(self):
        super(FindInt3, self).__init__("find_int3", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        hits = _search_bytes(b'\xCC')
        for a in hits:
            print(f"int3 instruction @ 0x{a:x}")

FindPtrace()
FindGetppid()
FindSignal()
FindForkPtrace()
FindInt3()

print("Anti-debug detectors loaded: find_ptrace, find_getppid, find_signal, find_fork_ptrace, find_int3")
