import string
import hashlib
from collections import defaultdict
import os
import pickle
import configs.analysis_config as config

from java.lang import UnsupportedOperationException
from ghidra.program.model.address.AddressRangeImpl import getMinAddress, getMaxAddress
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.block import SimpleBlockModel
from ghidra.util.task import DummyCancellableTaskMonitor
from ghidra.program.model.address import GenericAddress


FEATURES_PATH = config.FEATURES_PATH
FEATURE_CORPUS = config.FEATURE_CORPUS

printset = set(string.printable)
isprintable = lambda x: set(x).issubset(printset)

blockModel = SimpleBlockModel(currentProgram)
monitor = DummyCancellableTaskMonitor()


def recursively_convert_generic_address(obj):
    if isinstance(obj, GenericAddress):
        return obj.toString()
    elif isinstance(obj, list):
        return [recursively_convert_generic_address(item) for item in obj]
    elif isinstance(obj, dict):
        return {recursively_convert_generic_address(k): recursively_convert_generic_address(v) for k, v in obj.items()}
    elif isinstance(obj, tuple):
        return tuple(recursively_convert_generic_address(item) for item in obj)
    else:
        return obj


def store_func_data_adv(load_dir, bin_name, func_data_list, suffix=""):
    parts = bin_name.split(os.sep)

    # Get indices of relevant parts
    idx_vendor = parts.index('unpacked_dataset') + 1
    idx_firmware = idx_vendor + 2

    # Formulate the output string
    subpath = "{vendor}/{firmware}_{binary}{suf}.pickle".format(
        vendor=parts[idx_vendor],
        firmware=parts[idx_firmware][1:].replace(".extracted", ""),
        binary=parts[-1],
        suf=suffix
    )
    load_path = os.path.join(load_dir, subpath)

    with open(load_path, "wb") as f:
        pickle.dump(func_data_list, f)


def store_func_data(bin_name, func_data_list, suffix=""):
    base_name = os.path.basename(bin_name)
    data_name = base_name + suffix + ".pickle" #bin_name
    data_name = os.path.join(FEATURE_CORPUS, data_name)

    with open(data_name, "wb") as f:
        pickle.dump(func_data_list, f)


def get_consts(func):
    consts = []
    consts = []
    currentProgram = getCurrentProgram()
    instructions = currentProgram.getListing().getInstructions(func.getBody(), True)
    for instr in instructions:
        ops = instr.getOpObjects(0)
        for op in ops:
            if isinstance(op, Scalar):
                # if op.isScalar():
                imm_value = op.getUnsignedValue()
                consts.append(imm_value)
    return consts


def get_strings(func):
    # Get the start and end addresses of the function
    func_start = func.getBody().getMinAddress()
    func_end = func.getBody().getMaxAddress()

    # Get the program listing
    listing = currentProgram.getListing()

    # Get the instruction iterator
    instr_iter = listing.getInstructions(func_start, True)

    strings = []
    # Iterate over the instructions in the function
    for instr in instr_iter:
        # Check if we've reached the end of the function
        if instr.getMinAddress().compareTo(func_end) > 0:
            break

        refs = instr.getReferencesFrom()
        for ref in refs:
            if ref.getReferenceType().isData():
                s = get_string_at(toAddr(ref.getToAddress().getOffset()))
                if s and isprintable(s):
                    strings.append([instr.getAddress(), s, ref.getToAddress()])

    return strings


def get_call_graph():
    callee_map = defaultdict(list)
    caller_map = defaultdict(list)
    for callee_ea in currentProgram.getFunctionManager().getFunctions(True):
        callee = callee_ea.getBody()

        callee_name = callee_ea.getName()
        for caller_ea in getReferencesTo(callee_ea.getEntryPoint()):
            caller = getFunctionAt(caller_ea.getFromAddress())
            
            # Check if caller is not None
            if caller is None:
                continue
            
            caller_name = caller.getName()
            callee_map[caller_name].append([callee_name, callee_ea.getEntryPoint()])
            caller_map[callee_name].append([caller_name, caller_ea.getFromAddress()])

    return caller_map, callee_map


def get_bb_graph(caller_map, callee_map):
    edge_map = {}
    bb_callee_map = {}
    for function in currentProgram.getFunctionManager().getFunctions(True):
        func_ea = function.getEntryPoint()
        func_name = function.getName()
        edge_map[func_name] = []
        bb_callee_map[func_name] = []

        graph = function.getBody()
        if graph:
            for bb in graph:
                edge_map[func_name].append((bb.getMinAddress(), bb.getMaxAddress()))

            for callee_name, callee_ea in callee_map[func_name]:
                if graph.contains(callee_ea):
                    bb_callee_map[func_name].append((callee_name, callee_ea))

    return edge_map, bb_callee_map


def get_type(function):
    function_signature = str(function.getSignature())
    ret_type = str(function.getReturnType())
    args = function.getParameters()
    arg_data = []
    for i, arg in enumerate(args):
        try:
            arg_stack_offset = str(arg.getStackOffset())
        except UnsupportedOperationException:
            arg_stack_offset = None
        arg_data.append([i, arg.getName(), str(arg.getDataType()), arg_stack_offset])
    return [function_signature, ret_type, arg_data]


def get_string_at(addr):
    data = getDataAt(addr)
    if data is None:
        return None
    dt = data.getDataType()
    if isinstance(dt, ghidra.program.model.data.StringDataType):
        return str(data)
    else:
        return None


def get_bin_hash(file_path):
    with open(file_path, 'rb') as f:
        return hashlib.sha1(f.read()).hexdigest()


def main():
    bin_path = currentProgram.getExecutablePath()
    bin_hash = get_bin_hash(bin_path)
    img_base = currentProgram.getImageBase()
    info = currentProgram.getLanguage()
    endian = info.getLanguageDescription().getEndian()
    proc_name = info.getProcessor().toString()
    bits = info.getLanguageDescription().getSize()
    arch = "{}_{}_{}".format(proc_name, bits, endian)

    # Parsing options are not available in Ghidra
    package, compiler, arch, opti, bin_name = bin_path, None, arch, None, os.path.basename(bin_path)
    other_option = "normal"

    caller_map, callee_map = get_call_graph()
    edge_map, bb_callee_map = get_bb_graph(caller_map, callee_map)

    func_data = []
    functionManager = currentProgram.getFunctionManager()
    for idx, function in enumerate(functionManager.getFunctions(True)):
        func_ea = function.getEntryPoint()
        func_name = function.getName()

        demangled_name, demangled_full_name = function.getName(True), function.getPrototypeString(True, False)

        # memory = currentProgram.getMemory()
        byte_array = bytearray(function.getBody().getNumAddresses())
        # data = memory.getBytes(func_ea, byte_array)

        data_hash = hashlib.sha1(bytes(byte_array)).hexdigest()

        stack_size = function.getStackFrame().getFrameSize()

        # Get imported callees.
        imported_callees = []
        if func_name in callee_map:
            imported_callees = [item for item in callee_map[func_name] if not functionManager.getFunctionContaining(item[1])]

        # Get type information
        func_type, ret_type, args = get_type(function)

        # Prepare basic block information for feature extraction
        func_strings = []
        func_consts = []
        bb_data = []
        graph = function.getBody()

        for block in graph:
            minAddress = block.getMinAddress()
            maxAddress = block.getMaxAddress()
            length = maxAddress.subtract(minAddress)
            
            block_data = bytearray(length)
            block_data_hash = hashlib.sha1(bytes(block_data)).hexdigest()


            bb_strings = get_strings(function)
            bb_consts = get_consts(function)
            bb_callees = bb_callee_map.get(func_name, [])
            bb_data.append({
                "size": length, 
                "block_id": block.hashCode(),
                "startEA": block.getMinAddress(),
                "endEA": block.getMaxAddress(),
                "type": None, 
                "is_ret": function.hasNoReturn(),
                "hash": block_data_hash,
                "callees": bb_callees,
                "strings": bb_strings,
                "consts": bb_consts,
            })

        func_strings.extend(bb_strings)
        func_consts.extend(bb_consts)

        seg_name = ""
        for block in blockModel.getCodeBlocksContaining(func_ea, monitor):
            seg_name = block.getName()

        func_data.append({
            "ida_idx": idx,
            "seg_name": seg_name, 
            "name": func_name,
            "demangled_name": demangled_name,
            "demangled_full_name": demangled_full_name,
            "hash": data_hash,
            "size": function.getBody().getNumAddresses(),
            "startEA": function.getEntryPoint(),
            "endEA": function.getBody().getMaxAddress(),
            "cfg_size": len(edge_map.get(func_name, [])),
            "img_base": img_base,
            "bin_path": bin_path,
            "bin_hash": bin_hash,
            "bin_offset": func_ea.subtract(img_base),
            "stack_size": stack_size,
            "package": package,
            "compiler": compiler,
            "arch": arch,
            "opti": opti,
            "others": other_option,
            "bin_name": bin_name,
            "func_type": func_type,
            "ret_type": ret_type,
            "args": args,
            "callers": caller_map[func_name],
            "callees": callee_map[func_name],
            "imported_callees": imported_callees,
            "cfg": edge_map[func_name],
            "strings": func_strings,
            "consts": func_consts,
            "bb_data": bb_data,
            "abstract_args_type": args,
            "abstract_ret_type": ret_type
        })

    new_func_data = [recursively_convert_generic_address(func_data_item) for func_data_item in func_data]

    return new_func_data

try:
    func_data = main()
    bin_path = currentProgram.getExecutablePath()
    if 'unpacked_dataset' in bin_path:
        store_func_data_adv(FEATURES_PATH, bin_path, func_data)
    else:
        store_func_data(bin_path, func_data)
except:
    import traceback
    traceback.print_exc()
