import idc
import idautils
import idaapi
import ida_bytes
import ida_segment
import os
import tempfile
import time


def write_segment(va_start, va_end, segm_name, data):
    ida_segment.add_segm(0, va_start, va_end, segm_name, None, 0xe)
    va = va_start
    for b in data:
        ida_bytes.patch_byte(va, ord(b))
        va += 1
    print("wrote 0x%x bytes to 0x%x [%s]" % (len(data), va_start, segm_name))

def dump_segment(segm_name, from_debugger=True):
    segm = ida_segment.get_segm_by_name(segm_name)
    data_length = segm.end_ea - segm.start_ea
    return ida_bytes.get_bytes(segm.start_ea, data_length, from_debugger)

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
            idc.add_bpt(ea)
            bps.append(ea)
    return bps


class IDADbgHookDump(idaapi.DBG_Hooks):

    def __init__(self, hook_info):
        idaapi.DBG_Hooks.__init__(self)
        self.hooks = hook_info
        self.dumpdir = tempfile.mkdtemp(prefix="idaextutil_dump")

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
        for name in self.hooks[funcname]["buffer"]:
            ea_buffer = idc.get_name_ea_simple(name)
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

