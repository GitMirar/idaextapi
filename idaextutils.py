import idc
import idautils
import idaapi
import os
import tempfile
import time

import pyTycho

imgname = idc.get_input_file_path().split(os.path.sep)[-1]
service = None
proc = None


def initialize_tycho():
    global service, proc
    print("initializing tycho")
    service = pyTycho.Tycho()
    print("opening process with image %s" % imgname)
    proc = service.open_process(imgname)
    proc.pause()
    while not proc.is_running():
        time.sleep(1)
        print("waiting for process")
    # inject_pagefaults()
    proc.launch_gdb_stub(4141, 64)

def inject_pagefault(va):
    print("injecting pagefault at %x" % va)
    proc.get_thread_list()
    proc.inject_pagefault(va, 0x4)

def inject_pagefaults():
    proc.get_thread_list()
    vad = proc.get_vad_list()
    for node in vad:
        va_start = node.start_vpn * 0x1000
        va_end = node.end_vpn * 0x1000
        for page_start in range(va_start, va_end, 0x1000):
            if not proc.inject_pagefault(page_start, 0x4):
                print("could not inject pagefault at %x" % page_start)
            else:
                print("injected pagefault at %x" % va)

def find_references(funcname):
    referenced_locations = []
    func_ea = idc.LocByName(funcname)
    for ea in idautils.FuncItems(func_ea):
        i = 0
        while True:
            val = idc.GetOperandValue(ea, i)
            if val == -1:
                break
            i += 1
            name = idc.get_name(val)
            if name == "":
                continue
            referenced_locations.append(name)
    return referenced_locations

def filter_writable_segment(ea):
    return not idc.get_segm_attr(ea, idc.SEGATTR_PERM) & 2

def get_segments_filtered(filter_func=None):
    segments = []
    ea = idc.get_first_seg()
    while True:
        name = idc.get_segm_name(ea)
        if filter_func and filter_func(ea):
            ea = idc.get_next_seg(ea)
            if ea is idc.BADADDR:
                break
            continue
        if not name in segments:
            segments.append(name)
        ea = idc.get_next_seg(ea)
        if ea is idc.BADADDR:
            break
    return segments

def get_writable_segments():
    return get_segments_filtered(filter_func=filter_writable_segment)

def get_segments():
    return get_segments_filtered()

def filter_for_data(name_list):
    filtered = []
    for name in name_list:
        ea = idc.get_name_ea_simple(name)
        if idc.is_data(ea):
            filtered.append(name)
    return filtered

def filter_for_code(name_list):
    filtered = []
    for name in name_list:
        ea = idc.get_name_ea_simple(name)
        if idc.is_code(ea):
            filtered.append(name)

def find_references_data(funcname):
    refs = find_references(funcname)
    refs = filter_for_data(refs)
    return refs

def find_references_writable_data(funcname):
    refs = find_references(funcname)
    refs_filtered = []
    writable_segments = get_writable_segments()
    for ref in refs:
        name = idc.get_segm_name(idc.get_name_ea_simple(ref))
        if name == "":
            continue
        if name in writable_segments:
            refs_filtered.append(ref)
    return refs_filtered

def enable_bp_ret(funcname):
    func_ea = idc.get_name_ea_simple(funcname)
    bps = []
    for ea in idautils.FuncItems(func_ea):
        if idc.GetMnem(ea) == "retn":
            inject_pagefault(ea)
            idc.add_bpt(ea)
            bps.append(ea)
    return bps

class IDADbgHookDump(idaapi.DBG_Hooks):

    def __init__(self, hook_info):
        idaapi.DBG_Hooks.__init__(self)
        self.hooks = hook_info
        self.dumpdir = tempfile.mkdtemp(prefix="idaextutil_dump")

    def dbg_process_attach(self,  pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
        inject_pagefault(ea)
        for funcname in self.hooks:
            for ea in self.hooks[funcname]["bp"]:
                inject_pagefault(ea)


    def dbg_bpt(self, tid, ea):
        f_ea = idc.get_func_attr(ea, 0)
        if f_ea == idc.BADADDR:
            return 0
        funcname = idc.get_name(f_ea)
        print("hit breakpoint in thread %x at %s %x" % (tid, funcname, ea))
        if funcname == "":
            return 0
        if not funcname in self.hooks:
            return 0
        """
        if not ea in self.hooks[funcname]["bp"]:
            return 0
        """
        # inject_pagefaults()
        for name in self.hooks[funcname]["buffer"]:
            ea_buffer = idc.get_name_ea_simple(name)
            inject_pagefault(ea_buffer)
            data = get_bytes(ea_buffer, 0x1000)
            print("dumping %s" % name)
            print("%s" % [ "%02x" % ord(b) for b in data[:0x40] ])
            timestamp = time.time()
            dumpfile = os.path.join(self.dumpdir, "%s_%s_%f" % (funcname, name, timestamp))
            with open(dumpfile, "wb") as f:
                f.write(data)
            print("wrote buffer dump to %s" % dumpfile)
        idaapi.continue_process()
        return 0

    def get_hooks(self):
        return self.hooks

dbg_hook = None
def install_dbg_hook_dump(hooks):
    global dbg_hook
    bps = dict()
    # inject_pagefaults()
    for function in hooks:
        bps[function] = dict()
        bps[function]["bp"] = enable_bp_ret(function)
        bps[function]["buffer"] = hooks[function]
        print("installed hooks for function %s:" % function)
        for bp in bps[function]["bp"]:
            print("\tbp: %x" % bp)
        for b in bps[function]["buffer"]:
            print("\tbuffer: %s" % b)
    if not dbg_hook:
        dbg_hook = IDADbgHookDump(bps)
    dbg_hook.hook()

def remove_dbg_hook_dump():
    global dbg_hook
    if dbg_hook:
        dbg_hook.unhook()

def get_hooks(functions):
    hooks = dict()
    for func in functions:
        hooks[func] = find_references_writable_data(func)
    return hooks

def run():
    print("starting (%s) ..." % imgname)
    initialize_tycho()
    # functions = [ "_Z13do_some_stuffPc" ]
    functions = [ idc.get_name(f) for f in idautils.Functions() ]
    hooks = get_hooks(functions)
    install_dbg_hook_dump(hooks)



