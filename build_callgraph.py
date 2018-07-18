import idc
import idautils
import json
import tempfile

def find_functions(substring):
    ea = idc.get_first_seg()
    funcs = []
    while True:
        ea = idc.get_next_seg(ea)
        if ea is idc.BADADDR:
            break
        for func_ea in idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea)):
            func_name = idc.get_func_name(func_ea)
            if func_name == "" or not substring in func_name:
                continue
            print("matched function %s %x" % (func_name, func_ea))
            funcs.append(func_ea)
    return funcs

def find_functions_m(substring):
    ea = idc.get_first_seg()
    funcs = []
    while True:
        ea = idc.get_next_seg(ea)
        if ea is idc.BADADDR:
            break
        for func_ea in idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea)):
            func_name = idc.get_func_name(func_ea)
            if func_name == "" or not substring == func_name:
                continue
            print("matched exactly function %s %x" % (func_name, func_ea))
            funcs.append(func_ea)
    return funcs

def get_func_xrefs(ea):
    xrefs = []
    for xref in idautils.XrefsTo(ea, 1):
        if not xref.frm in xrefs:
            xrefs.append(xref.frm)
    return xrefs

def build_graph(substring):
    funcs = find_functions(substring)
    xrefs = dict()
    for func in funcs:
        xrefs[idc.get_func_name(func)] = []
        xrefs_ea = get_func_xrefs(func)
        for xref in xrefs_ea:
            if idc.get_func_name(xref) not in xrefs[idc.get_func_name(func)]:
                xrefs[idc.get_func_name(func)].append(idc.get_func_name(xref))
    return xrefs

def cleanup_data(data):
    new_data = dict()
    for func in data:
        funcdata = []
        if func.replace("j_", "")  not in new_data:
            new_data[func.replace("j_", "")] = []
        for xref in data[func]:
            if xref.replace("j_", "") not in new_data[func.replace("j_", "")]:
                new_data[func.replace("j_", "")].append(xref.replace("j_", ""))
    return new_data

def add_calls(funcdata):
    additions = dict()
    funcall_funcs = []
    for called in funcdata:
        if not called in funcall_funcs:
            funcall_funcs.append(called)
        for func in funcdata[called]:
            if not func in funcall_funcs:
                funcall_funcs.append(func)
    for func in funcall_funcs:
        for ins in idautils.FuncItems(idc.LocByName(func)):
            if idc.GetMnem(ins) == "call":
                called_func = idc.get_func_name(idc.GetOperandValue(ins, 0))
                if called_func != "":
                    called_func = called_func.replace("j_", "")
                    if not called_func in additions:
                        additions[called_func] = []
                    if not func in additions[called_func]:
                        additions[called_func].append(func)
    for cfunc in additions:
        if not cfunc in funcdata:
            funcdata[cfunc] = []
        for func in additions[cfunc]:
            if not func in funcdata[cfunc]:
                funcdata[cfunc].append(func)
    return funcdata

def json_dump(data):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(json.dumps(data))
        print("wrote data to %s" % f.name)


def build_clean_callgraph():
    data = build_graph("obfs")
    data2 = cleanup_data(data)
    data3 = add_calls(data2)
    json_dump(data3)
    return data3
