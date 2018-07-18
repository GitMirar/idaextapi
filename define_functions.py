import idc
import idautils

def is_code(ea):
    return idc.is_code(idc.get_full_flags(ea))

NUM_OBFSFUNC = dict()
def define_function(ea, prefix="obfsfunc_", num=None):
    global NUM_OBFSFUNC
    if num is None:
        if prefix not in NUM_OBFSFUNC:
            NUM_OBFSFUNC[prefix] = 0
        my_num = NUM_OBFSFUNC[prefix]
    else:
        my_num = num
    if idc.get_func_name(ea) != "":
        print("already defined func at %x" % ea)
        idc.MakeName(ea, "%s%d" % (prefix, my_num))
        if num is None:
            NUM_OBFSFUNC[prefix] += 1
        return my_num
    align_ea = ea - (ea % 0x8)
    idc.MakeByte(align_ea)
    idc.MakeCode(ea)
    idc.auto_wait()
    my_ea = ea
    if not idc.MakeFunction(ea):
        # seems like there is some data not recognized as code
        """
        while True:
            my_ea = idc.NextHead(my_ea)
            if not is_code(my_ea):
                print("Warning: could not declare as code: %x" % my_ea)
                # found the missing byte
                # idc.MakeCode(my_ea)
                break
        if not idc.MakeFunction(ea):
            print("Warning: could not define function at %x" % ea)
        """
        print("Warning: could not define function at %x" % ea)
        my_num = NUM_OBFSFUNC[prefix]
    else:
        idc.MakeName(ea, "%s%d" % (prefix, my_num))
        my_num = NUM_OBFSFUNC[prefix]
        if num is None:
            NUM_OBFSFUNC[prefix] += 1
        print("found function at %x" % ea)
    return my_num

def find_all(opcode_str):
    ret = []
    ea = idc.FindBinary(0, 1, opcode_str)
    while ea != idc.BADADDR:
        ret.append(ea)
        ea = idc.FindBinary(ea + len(opcode_str), 1, opcode_str)
    return ret

def fixups():
    pass


def define_all_obfs_funcs():
    global NUM_OBFSFUNC
    fixups()
    j_func_add = "E8 00 00 00 00 48 83 04 24 10 C3"
    j_func_push_mov = "55 48 89 E5"
    j_func_mov = "48 B8 1A F8 C8 FC 28 84 D5 65"
    j_func_mov_2 = "48 B8 74 A5 C9 F2 B9 AE C6 83"
    j_func_mov_3 = "48 B8 B6 E0 B8 5D 37 F2 54 87"
    j_func_mov_4 = "BA 67 66 66 66"
    j_func_mov_5 = "E8 9D FC FF FF"
    j_func_mov_6 = "E8 C5 F9 FF FF"
    j_func_mov_7 = "E8 F6 18 00 00"
    j_func_mov_7 = "48 B8 2D 7F 95 4C 2D F4 51 58"
    offset_func = 0x15
    offset_byte_0 = 0xb
    offset_byte_2 = 0x8
    j_func_else_list = find_all(j_func_mov)
    j_func_else_list_2 = find_all(j_func_mov_2)
    j_func_else_list_3 = find_all(j_func_mov_3)
    j_func_else_list_4 = find_all(j_func_mov_4)
    j_func_else_list_5 = find_all(j_func_mov_5)
    j_func_else_list_6 = find_all(j_func_mov_6)
    j_func_else_list_7 = find_all(j_func_mov_7)
    j_func_else_list_8 = find_all(j_func_mov_8)
    [ j_func_else_list.append(f) for f in j_func_else_list_2 ]
    [ j_func_else_list.append(f) for f in j_func_else_list_3 ]
    [ j_func_else_list.append(f) for f in j_func_else_list_4 ]
    [ j_func_else_list.append(f) for f in j_func_else_list_5 ]
    [ j_func_else_list.append(f) for f in j_func_else_list_6 ]
    [ j_func_else_list.append(f) for f in j_func_else_list_7 ]
    [ j_func_else_list.append(f) for f in j_func_else_list_8 ]
    if "obfsfunc_" not in NUM_OBFSFUNC:
        NUM_OBFSFUNC["obfsfunc_"] = 0
    for ea in j_func_else_list:
        if idc.get_func_name(ea) != "":
            ea_begin = idc.get_func_attr(ea, 0)
            idc.MakeName(ea_begin, "obfsfunc_%d" % NUM_OBFSFUNC["obfsfunc_"])
            NUM_OBFSFUNC["obfsfunc_"] += 1

    j_func_add_ea_list = find_all(j_func_add)
    for ea in j_func_add_ea_list:
        idc.MakeByte(ea + offset_byte_0)
        offset_byte_1 = 0x10 - (ea % 0x8)
        idc.MakeByte(ea + offset_byte_1)
        num = define_function(ea + offset_func)
        j_func_ea = idc.FindBinary(ea, 0, j_func_push_mov)
        if j_func_ea != idc.BADADDR:
            define_function(j_func_ea, "j_obfsfunc_", num=num)



