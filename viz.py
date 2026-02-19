"""
0xtengu

teaching visualizer for pwndbg
shows a window into memory

usage:
    viz $rsp        # center view around stack pointer
    viz &buf        # show memory at buffer
    viz 0x404000    # show memory at address
    viz $rsp 0x100  # show 256 bytes around stack pointer

linux x86_64 only
"""

import gdb
import struct
import re
import os

# /////////////////////////////////////////////////////////
# /////////////////////////////////////////////// CONFIG
# /////////////////////////////////////////////////////////

DEFAULT_VIEW_SIZE = 0x80  # 128 bytes
QWORD_SIZE = 8

STACK_ADDR_MIN = 0x00007f0000000000
STACK_ADDR_MAX = 0x00007fffffffffff
EXE_ADDR_MIN = 0x0000000000400000
EXE_ADDR_MAX = 0x00000000006fffff

PIE_LOAD_ADDR = 0x0000555555554000
NONPIE_ADDR_MIN = 0x0000000000400000
NONPIE_ADDR_MAX = 0x0000000000600000

CANARY_MIN_VALUE = 0x100000
CANARY_MAX_DISTANCE_FROM_RBP = 0x20

STRING_PREVIEW_LENGTH = 16

ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_INV = "\x1b[7m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_MAGENTA = "\x1b[35m"
ANSI_CYAN = "\x1b[36m"
ANSI_GRAY = "\x1b[90m"

COLOR_BORDER = ANSI_GRAY       
COLOR_ADDRESS = ANSI_CYAN      
COLOR_QWORD = ANSI_GRAY        
COLOR_ASCII = ANSI_MAGENTA     
COLOR_POINTER = ANSI_YELLOW    
COLOR_HEADER = ANSI_BOLD       

COLOR_BUFFER = ANSI_GREEN      
COLOR_LOCAL = ANSI_CYAN        
COLOR_SAVED_RBP = ANSI_YELLOW  
COLOR_SAVED_RIP = ANSI_RED     
COLOR_CANARY = ANSI_INV        

# /////////////////////////////////////////////////////////
#   CLASSES //////////////////////////////////////////////
# ///////////////////////////////////////////////////////

# tracks a local variable or buffer on the stack
class Region:
    def __init__(self, start, length, name, color_code, kind):
        self.start = int(start)
        self.end = int(start + length)
        self.name = name
        self.color = color_code
        self.kind = kind  # "buffer" or "local"
    
    def contains(self, addr):
        return self.start <= addr < self.end

# single memory mapping from /proc/pid/maps
class MapEntry:
    def __init__(self, start, end, perms, path):
        self.start = start
        self.end = end
        self.perms = perms
        self.path = path

# /////////////////////////////////////////
# // UTILS /////////////////////////////////////
# ///////////////////////////////////////////////////

def color(text, code):
    return f"{code}{text}{ANSI_RESET}"

def parseArgs(arg_string):
    return gdb.string_to_argv(arg_string)

def roundUp(n, align):
    return (n + (align - 1)) & ~(align - 1)

def roundDown(n, align):
    return n & ~(align - 1)

def evalExpr(expr):
    return int(gdb.parse_and_eval(expr))

def readMemory(addr, size):
    inferior = gdb.selected_inferior()
    mem = inferior.read_memory(addr, size)
    return bytes(mem)

def unpackQword(data):
    return struct.unpack("<Q", data)[0]

def isPrintable(byte):
    return 32 <= byte <= 126

def isValidStackAddr(addr):
    return STACK_ADDR_MIN <= addr <= STACK_ADDR_MAX

# pointer detection
def looksLikePointer(value):
    return (STACK_ADDR_MIN <= value <= STACK_ADDR_MAX) or \
           (EXE_ADDR_MIN <= value <= EXE_ADDR_MAX)

def tryReadCstring(addr, max_len=STRING_PREVIEW_LENGTH):
    try:
        data = readMemory(addr, max_len)
    except:
        return None
    
    chars = []
    for b in data:
        if b == 0:
            break
        chars.append(chr(b) if isPrintable(b) else ".")
    
    if not chars:
        return None
    
    result = "".join(chars)
    if len(result) == max_len:
        result += "…"
    return result

# canary detection
def looksLikeCanary(value):

    if value == 0 or (value & 0xFF) != 0: # must be non-zero with null lsb
        return False
    
    # upper bytes must be non-zero
    if (value >> 8) == 0:
        return False
    
    if looksLikePointer(value) or value < CANARY_MIN_VALUE:
        return False
    
    return True

def isLikelyCanaryPosition(addr, rbp, regions):
    if rbp is None:
        return False
    
    if addr == rbp - 8: # generaly right before saved rbp
        return True
    
    # sometimes further away but after a buffer
    if rbp - CANARY_MAX_DISTANCE_FROM_RBP <= addr < rbp:
        for r in regions:
            if r.kind == "buffer" and r.end <= addr:
                return True
    
    return False

# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[
# ---[ /proc/pid/maps parsing ]---
# ]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]

_maps_cache = {}
_exe_path_cache = None

def getExePath():
    global _exe_path_cache
    if _exe_path_cache is not None:
        return _exe_path_cache if _exe_path_cache else None
    
    try:
        path = gdb.current_progspace().filename
        if path:
            _exe_path_cache = path
            return path
    except:
        pass
    
    _exe_path_cache = ""
    return None

def pathMatchesExe(map_path, exe_path):
    if not exe_path or not map_path:
        return False
    
    if map_path == exe_path:
        return True
    if os.path.basename(map_path) == os.path.basename(exe_path):
        return True
    return False

def loadMaps(pid):
    if pid in _maps_cache:
        return _maps_cache[pid]
    
    entries = []
    stack_range = None
    heap_range = None
    
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            for line in f:
                m = re.match(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)$", 
                           line.strip())
                if not m:
                    continue
                
                start = int(m.group(1), 16)
                end = int(m.group(2), 16)
                perms = m.group(3)
                path = m.group(4).strip()
                
                entries.append(MapEntry(start, end, perms, path))
                
                if path == "[stack]":
                    stack_range = (start, end)
                elif path == "[heap]":
                    heap_range = (start, end)
    except:
        pass
    
    result = (entries, stack_range, heap_range)
    _maps_cache[pid] = result
    return result

def isPieEnabled():
    exe = getExePath()
    if not exe:
        return False
    
    try:
        pid = int(gdb.selected_inferior().pid)
        if pid == 0:
            return False
        
        entries, _, _ = loadMaps(pid)
        for e in entries:
            if pathMatchesExe(e.path, exe):
                if e.start >= PIE_LOAD_ADDR:
                    return True
                if NONPIE_ADDR_MIN <= e.start <= NONPIE_ADDR_MAX:
                    return False
        return False
    except:
        return False

def classifyPointer(pid, addr):
    entries, stack_range, heap_range = loadMaps(pid)
    exe = getExePath()
    
    # check special ranges
    if stack_range and stack_range[0] <= addr < stack_range[1]:
        return "stack"
    if heap_range and heap_range[0] <= addr < heap_range[1]:
        return "heap"
    
    # check all mappings
    for e in entries:
        if e.start <= addr < e.end:
            path = e.path
            
            # main executable
            if pathMatchesExe(path, exe):
                # check for plt/got
                try:
                    section_info = gdb.execute(f"info symbol {addr:#x}", to_string=True)
                    if ".plt" in section_info:
                        return "plt"
                    if ".got" in section_info or "got.plt" in section_info:
                        return "got"
                except:
                    pass
                
                return "exe:text" if "x" in e.perms else "exe:data"
            
            # special mappings
            if path in ("[vdso]", "[vvar]"):
                return path.strip("[]")
            
            if path == "":
                return "anon"
            
            # libraries
            if "libc" in path:
                return "libc"
            if "ld-" in path or "ld-linux" in path:
                return "ld"
            
            if "x" in e.perms:
                return "code"
            
            return "mapped"
    
    return "unknown"

# /////////////////////////////////////////////////////////
# \\\\\\\\\\\\\\\ DETECT LOCAL VARIABLES ///////////////////
# ///////////////////////////////////////////////////////////

def iterFrameSymbols(frame):
    try:
        block = frame.block()
    except:
        return
    
    seen = set()
    while block is not None:
        for sym in block:
            try:
                if not (sym.is_variable or sym.is_argument):
                    continue
                if not sym.is_valid():
                    continue
                
                name = sym.print_name
                if not name or name in seen:
                    continue
                
                seen.add(name)
                yield sym
            except:
                continue
        
        if block.function is None:
            break
        block = block.superblock

def isByteType(gdb_type):
    try:
        t = gdb_type.strip_typedefs()
        return t.code == gdb.TYPE_CODE_INT and int(t.sizeof) == 1
    except:
        return False

def detectArrays():
    regions = []
    
    try:
        frame = gdb.selected_frame()
    except:
        return regions
    
    for sym in iterFrameSymbols(frame):
        try:
            val = sym.value(frame)
            ty = val.type.strip_typedefs()
            
            if ty.code != gdb.TYPE_CODE_ARRAY:
                continue
            
            size = int(ty.sizeof)
            if size <= 0 or size > 0x10000:
                continue
            
            addr = int(val.address)
            elem = ty.target().strip_typedefs()
            name = sym.print_name
            
            # byte arrays are potential overflow targets
            if isByteType(elem):
                regions.append(Region(addr, size, name, COLOR_BUFFER, "buffer"))
            else:
                regions.append(Region(addr, size, name, COLOR_LOCAL, "local"))
        except:
            continue
    
    # sort and deduplicate
    regions.sort(key=lambda r: (r.start, -(r.end - r.start), r.name))
    
    unique = []
    seen = set()
    for r in regions:
        key = (r.start, r.end, r.name)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    
    return unique

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#   0000000000000000000 COLORS! 0000000000000000000000000
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

def getByteColor(addr, qword_val, qword_addr, regions, rbp, saved_rip_addr):
    # priority: canary > saved_rip > saved_rbp > regions
    
    # check if part of canary
    if qword_val and looksLikeCanary(qword_val):
        if isLikelyCanaryPosition(qword_addr, rbp, regions):
            if qword_addr <= addr < qword_addr + 8:
                return COLOR_CANARY
    
    # saved rip 
    if saved_rip_addr and saved_rip_addr <= addr < saved_rip_addr + 8:
        return COLOR_SAVED_RIP
    
    # saved rbp
    if rbp and rbp <= addr < rbp + 8:
        return COLOR_SAVED_RBP
    
    # check regions 
    for r in regions:
        if r.contains(addr):
            return r.color
    
    return None

# /////////////////////////////////////////////////////////
# LABELING -------------------------------------------- ///    
# /////////////////////////////////////////////////////////

def getRowLabel(addr, qword_val, regions, rbp, rsp, saved_rip_addr, regs):
    # check canary first
    if qword_val and looksLikeCanary(qword_val):
        if isLikelyCanaryPosition(addr, rbp, regions):
            return "canary"
    
    labels = []
    
    # check special stack addresses
    if saved_rip_addr and addr == saved_rip_addr:
        labels.append("saved_rip")
    elif rbp and addr == rbp:
        labels.append("saved_rbp")
    elif rsp and addr == rsp:
        labels.append("rsp")
    
    # check other registers
    if not labels:
        for reg_name in ['rax', 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']:
            reg_val = regs.get(reg_name)
            if reg_val and reg_val == addr:
                labels.append(reg_name)
    
    # check buffer variables
    if not labels:
        for r in regions:
            if r.contains(addr):
                delta = addr - r.start
                if delta == 0:
                    labels.append(r.name)
                else:
                    labels.append(f"{r.name}+{delta:#x}")
                break
    
    return "/".join(labels) if labels else ""

def getRowNote(addr, qword_val, rbp, saved_rip_addr, saved_rip_val, regions):
    # canary warning
    if qword_val and looksLikeCanary(qword_val):
        if isLikelyCanaryPosition(addr, rbp, regions):
            return color("⚠ STACK CANARY (stack smashing protection)", COLOR_CANARY)
    
    # saved rbp
    if rbp and addr == rbp:
        return color("saved RBP slot", COLOR_SAVED_RBP)
    
    # saved rip
    if saved_rip_addr and addr == saved_rip_addr:
        if saved_rip_val:
            return color(f"saved RIP (return addr) → {saved_rip_val:#x}", COLOR_SAVED_RIP)
        return color("saved RIP (return addr)", COLOR_SAVED_RIP)
    
    return ""

# ////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
#            RENDER TIME BABY
# ////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

def renderRow(pid, addr, offset, chunk, byte_colors, label, note, regs, regions, pad=18):
    blank = " " * pad
    corner = color("+", COLOR_BORDER)
    
    # format label with offset
    label_text = f"+{offset:#04x} {label}" if label else f"+{offset:#04x}"
    label_padded = f"{label_text:<{pad}}"
    
    # top border with address
    top_line = (
        f"{blank}"
        f"{corner}{color('-----------', COLOR_BORDER)} "
        f"{color(f'{addr:#x}', COLOR_ADDRESS)} "
        f"{color('------------', COLOR_BORDER)}{corner}"
    )
    if note:
        top_line += f"  {note}"
    
    # hex bytes with colors
    hex_bytes = []
    for i, byte in enumerate(chunk):
        hex_str = f"{byte:02x}"
        if byte_colors[i]:
            hex_str = color(hex_str, byte_colors[i])
        hex_bytes.append(hex_str)
    
    hex_display = (" " + color("|", COLOR_BORDER) + " ").join(hex_bytes)
    
    # qword value and pointer info
    qword_str = ""
    ptr_str = ""
    
    if len(chunk) == 8:
        qword_val = unpackQword(chunk)
        
        # check for canary
        if looksLikeCanary(qword_val) and isLikelyCanaryPosition(addr, regs.get("rbp"), regions):
            qword_str = color(f'  {qword_val:#018x}', COLOR_CANARY)
            ptr_str = f"  {color('CANARY', COLOR_CANARY)}"
        else:
            qword_str = color(f'  {qword_val:#018x}', COLOR_QWORD)
            
            # check if pointer
            if looksLikePointer(qword_val) and pid > 0:
                region = classifyPointer(pid, qword_val)
                ptr_str = f"  {color('→', COLOR_ADDRESS)}{color(region, COLOR_POINTER)}"
                
                # try to preview string
                preview = tryReadCstring(qword_val)
                if preview:
                    ptr_str += f" {color(preview, COLOR_ASCII)}"
    
    # ascii representation
    ascii_chars = "".join(chr(b) if isPrintable(b) else "." for b in chunk)
    ascii_str = f"  {color(ascii_chars, COLOR_ASCII)}"
    
    # middle line
    mid_line = (
        f"{label_padded}"
        f"{color('| ', COLOR_BORDER)}{hex_display}{color(' |', COLOR_BORDER)}"
        f"{qword_str}{ascii_str}{ptr_str}"
    )
    
    # bottom border
    bot_line = f"{blank}{corner}{color('---------------------------------------', COLOR_BORDER)}{corner}"
    
    return "\n".join([top_line, mid_line, bot_line])

#################################################
###############   HEADER & LEGEND   #############
#################################################

def printHeader(expr, expr_val, mode, base, length, regs, saved, regions, notes):
    end = base + length
    pid = int(gdb.selected_inferior().pid) if gdb.selected_inferior() else 0
    
    kind = "unknown"
    if pid > 0:
        kind = classifyPointer(pid, base)

    pie_status = "PIE" if isPieEnabled() else "no PIE"
    
    gdb.write("\n")
    gdb.write(f"{color('EXPR', COLOR_HEADER)}: {color(expr, COLOR_ADDRESS)} = {color(hex(expr_val), COLOR_ADDRESS)}  ")
    gdb.write(f"{color('mode=', COLOR_BORDER)}{color(mode, COLOR_BORDER)}\n")
    
    gdb.write(f"{color('VIEW', COLOR_HEADER)}: base={color(hex(base), COLOR_ADDRESS)}  ")
    gdb.write(f"end={color(hex(end), COLOR_ADDRESS)}  ")
    gdb.write(f"len={color(hex(length), COLOR_ADDRESS)}  ")
    gdb.write(f"kind={color(kind, COLOR_BORDER)}  {color(pie_status, COLOR_POINTER)}\n")
    
    gdb.write(f"{color('ANCHORS', COLOR_HEADER)}: ")
    gdb.write(f"RIP={color(hex(regs.get('rip')) if regs.get('rip') else '<?>', COLOR_BORDER)}  ")
    gdb.write(f"RSP={color(hex(regs.get('rsp')) if regs.get('rsp') else '<?>', COLOR_BORDER)}  ")
    gdb.write(f"RBP={color(hex(regs.get('rbp')) if regs.get('rbp') else '<?>', COLOR_BORDER)}\n")
    
    # saved slots (if relevant)
    saved_rbp_addr = saved.get("saved_rbp_addr")
    saved_rip_addr = saved.get("saved_rip_addr")
    
    if saved_rip_addr:
        in_view = (base <= saved_rbp_addr < end) or (base <= saved_rip_addr < end)
        if in_view or kind == "stack":
            saved_rip_val = saved.get('saved_rip_val')
            rip_str = hex(saved_rip_val) if saved_rip_val else '<unreadable>'
            
            gdb.write(f"{color('SAVED', COLOR_HEADER)}: ")
            gdb.write(f"saved_rbp_slot={color(hex(saved_rbp_addr), COLOR_SAVED_RBP)}  ")
            gdb.write(f"saved_rip_slot={color(hex(saved_rip_addr), COLOR_SAVED_RIP)}  ")
            gdb.write(f"saved_rip={color(rip_str, COLOR_SAVED_RIP)}\n")
    
    # notes
    gdb.write(f"{color('NOTE', COLOR_HEADER)}: stack grows toward lower addresses (↓)\n")
    if not isPieEnabled():
        gdb.write("      ASLR is active (stack/libs randomized by kernel), but exe has fixed base (no PIE)\n")
    
    has_buffer = any(r.kind == "buffer" and base <= r.start < end for r in regions)
    has_local = any(r.kind == "local" and base <= r.start < end for r in regions)
    
    gdb.write(f"{color('LEGEND', COLOR_HEADER)}:\n")
    if has_buffer:
        gdb.write(f"  {color('buffer-like arrays', COLOR_BUFFER)}  (auto-detected char/byte arrays)\n")
    if has_local:
        gdb.write(f"  {color('other arrays', COLOR_LOCAL)}  (auto-detected non-byte arrays)\n")
    
    if saved_rip_addr and (in_view or kind == "stack"):
        gdb.write(f"  {color('saved_rbp', COLOR_SAVED_RBP)}  ($rbp slot)\n")
        gdb.write(f"  {color('saved_rip', COLOR_SAVED_RIP)}  ($rbp+8 return address slot)\n")
        gdb.write(f"  {color('canary', COLOR_CANARY)}  (stack smashing protection - detects overflows)\n")
    
    gdb.write(f"  {color('→', ANSI_CYAN)}{color('region', COLOR_POINTER)}  (pointer to memory region: stack/heap/libc/exe/etc)\n")
    
    # extra notes
    for n in notes:
        gdb.write(n + "\n")
    
    gdb.write("\n")

#=====================================================#
# MAIN RENDER OPS                 { :D }
#=====================================================#

def renderView(expr, expr_val, mode, base, length, regs, saved, regions, notes):
    # read memory
    try:
        data = readMemory(base, length)
    except Exception as e:
        gdb.write(f"error reading memory: {e}\n")
        return
    
    # print header
    printHeader(expr, expr_val, mode, base, length, regs, saved, regions, notes)
    
    # get pid for pointer classification
    pid = int(gdb.selected_inferior().pid) if gdb.selected_inferior() else 0
    
    # render each row
    for offset in range(0, length, QWORD_SIZE):
        addr = base + offset
        chunk = data[offset:offset + QWORD_SIZE]
        qword_val = unpackQword(chunk) if len(chunk) == 8 else None
        
        # get label and note
        label = getRowLabel(addr, qword_val, regions, 
                            regs.get("rbp"), regs.get("rsp"), 
                            saved.get("saved_rip_addr"), regs)
        
        note = getRowNote(addr, qword_val, regs.get("rbp"),
                          saved.get("saved_rip_addr"), 
                          saved.get("saved_rip_val"), regions)
        
        # determine byte colors
        colors = [None] * 8
        for i in range(8):
            byte_addr = addr + i
            colors[i] = getByteColor(byte_addr, qword_val, addr, regions,
                                      regs.get("rbp"), saved.get("saved_rip_addr"))
        
        # render and print
        output = renderRow(pid, addr, offset, chunk, colors, label, note, regs, regions)
        gdb.write(output + "\n")

# /////////////////////////////////////////////////////////
# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\    HELPERS
# /////////////////////////////////////////////////////////

def getRegisters():
    regs = {}
    
    # core registers
    for r in ("$rip", "$rsp", "$rbp"):
        try:
            regs[r[1:]] = evalExpr(r)
        except:
            regs[r[1:]] = None
    
    # argument/return registers
    for r in ("$rax", "$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"):
        try:
            regs[r[1:]] = evalExpr(r)
        except:
            regs[r[1:]] = None
    
    return regs

def getSavedSlots(regs):
    saved = {
        "saved_rbp_addr": None,
        "saved_rip_addr": None,
        "saved_rip_val": None
    }
    
    rbp = regs.get("rbp")
    if rbp and isValidStackAddr(rbp):
        saved["saved_rbp_addr"] = rbp
        saved["saved_rip_addr"] = rbp + 8
        
        try:
            saved["saved_rip_val"] = unpackQword(readMemory(rbp + 8, 8))
        except:
            pass
    
    return saved

def computeOffsets(regions, saved, base, length):
    notes = []
    
    # find smallest buffer (closest to saved rbp/rip)
    buffers = [r for r in regions if r.kind == "buffer"]
    if not buffers:
        return notes
    
    primary = (sorted(buffers, key=lambda r: r.end - r.start)[0])
    
    saved_rbp_addr = saved.get("saved_rbp_addr")
    saved_rip_addr = saved.get("saved_rip_addr")
    
    if not saved_rbp_addr or not saved_rip_addr:
        return notes
    
    # only show if relevant to view
    end = base + length
    buf_in_view = primary.start < end and primary.end > base
    saved_in_view = (base <= saved_rbp_addr < end) or (base <= saved_rip_addr < end)
    
    pid = int(gdb.selected_inferior().pid) if gdb.selected_inferior() else 0
    is_stack = classifyPointer(pid, base) == "stack" if pid > 0 else False
    
    if not (buf_in_view or saved_in_view or is_stack):
        return notes
    
    off_rbp = saved_rbp_addr - primary.start
    off_rip = saved_rip_addr - primary.start
    
    # sanity check
    if -0x1000 <= off_rbp <= 0x4000 and -0x1000 <= off_rip <= 0x4000:
        notes.append(
            f"{color('OFFSETS', COLOR_HEADER)}: "
            f"{color(primary.name, COLOR_BUFFER)}→saved_rbp = {color(hex(off_rbp), COLOR_BORDER)} ({off_rbp})   "
            f"{color(primary.name, COLOR_BUFFER)}→saved_rip = {color(hex(off_rip), COLOR_BORDER)} ({off_rip})"
        )
    
    return notes

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# GDB COMMANDS   ===========================================
# ----------------------------------------------------------

class Viz(gdb.Command):
    
    def __init__(self):
        super(Viz, self).__init__("viz", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        # check we have a running inferior
        try:
            inferior = gdb.selected_inferior()
            pid = int(inferior.pid)
        except:
            gdb.write("viz: no active inferior (run the program first)\n")
            return
        
        if pid == 0:
            gdb.write("viz: no active inferior (run the program first)\n")
            return
        
        # parse arguments
        args = parseArgs(arg)
        if not args:
            gdb.write("usage: viz EXPR [LEN]\n")
            gdb.write("try: viz $rsp  or  viz &buf  or  viz 0x7fffffffe000\n")
            return
        
        expr = args[0]
        length = DEFAULT_VIEW_SIZE
        
        if len(args) >= 2:
            try:
                length = int(args[1], 0)
            except:
                gdb.write("error: LEN must be a number (e.g., 0x80 or 128)\n")
                return
        
        if length <= 0:
            gdb.write("error: LEN must be > 0\n")
            return
        
        # round up to qword alignment
        length = roundUp(length, QWORD_SIZE)
        
        # get current state
        regs = getRegisters()
        saved = getSavedSlots(regs)
        regions = detectArrays()
        
        # evaluate expression
        try:
            expr_val = evalExpr(expr)
        except Exception as e:
            gdb.write(f"error: could not evaluate '{expr}': {e}\n")
            return
        
        # determine mode and base address
        mode = "center" if expr.startswith("$") else "base"
        
        if mode == "center":
            base = roundDown(expr_val - (length // 2), QWORD_SIZE)
        else:
            base = roundDown(expr_val, QWORD_SIZE)
        
        notes = []
        
        # validate readability, fallback to $rsp if needed
        try:
            readMemory(base, 1)
            readMemory(base + length - 1, 1)
        except:
            rsp = regs.get("rsp")
            if not rsp:
                gdb.write("error: base not readable and $rsp unavailable\n")
                return
            
            base = roundDown(rsp - (length // 2), QWORD_SIZE)
            notes.append(color("FALLBACK: view not readable, showing stack around $rsp", COLOR_POINTER))
            mode = "fallback"
        
        # compute offset notes
        notes.extend(computeOffsets(regions, saved, base, length))
        
        # render view
        renderView(expr, expr_val, mode, base, length, regs, saved, regions, notes)

Viz()