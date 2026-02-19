
# pwnviz 

>[!NOTE]
Inspired by ret2 wargame's memory window

#### What

    A pwndbg extension that visualizes memory to teach exploit development.

#### Why

    Teaching exploitdev is easier when students can SEE the memory byte-by-byte. 

#### Usage

    (gdb) source viz.py
    (gdb) viz $rsp          # view stack around rsp
    (gdb) viz &buf          # view memory at buffer
    (gdb) viz 0x404000      # view specific address
    (gdb) viz $rbp 0x100    # view 256 bytes around rbp

#### Output
```gdb
                    +----------- 0x7fffffffdb30 ------------+
    +0x40 rsp       | 00 | 00 | 00 | 00 | 00 | 00 | 00 | 00 |  0x0000000000000000  ........
                    +---------------------------------------+
    
                    +----------- 0x7fffffffdb48 ------------+  saved RIP (return addr) → 0x4004dc
    +0x58 saved_rip | dc | 04 | 40 | 00 | 00 | 00 | 00 | 00 |  0x00000000004004dc  ..@.....  →exe:text
                    +---------------------------------------+
```
