# bbm
import time
import sys
# import ast

from ghidra.util.classfinder import ClassSearcher
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer
from ghidra.program.util import SymbolicPropogator
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import CancelledException
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
from collections import Counter, defaultdict

import json
import os
import stat


# findcrypt
import functools
import struct
# import crypt const
import const
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

# findIPC
import re
from ghidra.program.util import DefinedDataIterator


# ----------FIRMWARE UPDATE-RELATED KEYWORDS------------
# checksumWords = ['checksum', 'md5', 'sha256', 'crc', 'hash', 'md5sum', 'sha256sum', 'cksum']
# deviceWords = ['modulename', 'device', 'platform']
# versionWords = ['version', 'fwtool']
# signWords = ['signature', 'rsasign', 'rsa', 'certificate', 'cert'] #'sign',
signWords = ['RSA_verify', 'DSA_verify', 'ECDSA_do_verify', 'RsaSSL_Verify', 'DsaVerify', 'ecc_verify_hash', 'rsa_verify_hash', 'dsa_verify_hash', 'ecc_verify_hash', 'rsa_pkcs1_verify', 'ecdsa_verify', 'rsa_sha512_verify', 'dsa_verify', 'ecdsa_verify', 'HMAC_Update', 'CMAC_Update', 'Poly1305_Update', 'HmacUpdate', 'CmacUpdate', 'Poly1305Update', 'hmac_process', 'omac_process', 'poly1305_process', 'cipher_cmac_update', 'md_hmac_update', 'poly1305_update', 'hmac_sha1_update', 'cmac_aes128_update', 'poly1305_aes_update']
checksumWords = ['SHA256_Update', 'SHA3_absorb', 'RIPEMD160_Update', 'Sha256Update', 'Sha3_512_Update', 'RipeMdUpdate', 'sha256_process', 'sha3_process', 'rmd160_process', 'sha256_update_ret', 'sha512_process', 'ripemd160_update_ret', 'sha256_update', 'sha3_update', 'ripemd160_update', 'MD4_Update', 'MD5_Update', 'SHA1_Update', 'Md4Update', 'Md5Update', 'ShaUpdate', 'md4_process', 'md5_process', 'sha1_process', 'md4_update_ret', 'md5_update_ret', 'sha1_update_ret', 'md4_update', 'md5_update', 'sha1_update', 'crc']

deviceWords = ['get_modelid', 'fw_check', 'check_imagefile', 'check_imageheader', 'get_productid', 'upgradeCgiCheck', 'getProductId', 'is_valid_hwid', 'findStrInFile', 'check_hw_type']
versionWords = ['current_firm', 'firmware_version', 'upgradeCgiCheck', 'getProductVer', 'board_identify', 'check_image_version', 'findStrInFile', ]


rebootWords = ["reboot", "bin/reboot"]
writeWords = ["mtd", "bin/mtd", "flash"]
deliveryWords = ["wget", "bin/wget"]


# findIPC
def find_IPC():
    # outfile = open(results_file, "w")
    kws = set()
    fp_strs = set()
    fps = set()

    pattern = re.compile(r'((?:[A-Z]:|(?<![:/])[\/]|\~[\/]|(?:\.{1,2}[\/])+)[\w+\s_\-\(\)\/]*(?:\.\w+)*)')

    for string in DefinedDataIterator.definedStrings(currentProgram):
        references = getReferencesTo(string.getAddress())
        if references:
            keyword = str(string.toString()).replace('ds "', '').replace('"','')
            kws.add(string) #keyword
            # outfile.write(keyword+"\n")

            filepaths = pattern.findall(keyword)
            filepaths = [path.strip().strip("'").strip('"') for path in filepaths] #.strip('\\n').strip('\\')
            fp_strs = fp_strs | set(filepaths)
            
            if filepaths:
                fps.add(string)
    
    # get the reference address of filepaths
    fp_addrs = {}
    for fp in fps:
        fp_str = str(fp.toString()).replace('ds "', '').replace('"','')
        references = getReferencesTo(fp.getAddress())
        fp_addrs[fp_str] = []
        for r in references:
            r_addr = r.getFromAddress()
            fp_addrs[fp_str].append(str(r_addr))
    
    return kws, fp_strs, fp_addrs

        

# findcrypt
# ghidra api
# def find(find_bytes, min_addr=None):
#     min_addr = min_addr or currentProgram.getMinAddress()
#     return currentProgram.getMemory().findBytes(min_addr, find_bytes, None, True, monitor)

def create_label(addr, label_name, source=SourceType.USER_DEFINED):
    sym_table = currentProgram.getSymbolTable()
    sym_table.createLabel(addr, label_name, source)

def get_instructions_from(addr=None):
    return currentProgram.getListing().getInstructions(addr, True)

def get_all_instructions():
    return currentProgram.getListing().getInstructions(True)

def get_instruction_at(addr):
    return getInstructionAt(addr)

def get_memory_address_ranges():
    return currentProgram.getMemory().getAddressRanges()

def has_scalar_operand(inst, idx=1):
    return inst.getScalar(idx) is not None

def set_eol_comment(addr, text):
    code_unit = currentProgram.getListing().getCodeUnitAt(addr)
    code_unit.setComment(CodeUnit.EOL_COMMENT, text)

def get_function_containing(addr):
    return getFunctionContaining(addr)

def get_instructions_in_func(func):
    inst = get_instruction_at(func.getEntryPoint())
    while inst and getFunctionContaining(inst.getAddress()) == func:
        yield inst
        inst = inst.getNext()


# partial funcs
pack_longlong = functools.partial(struct.pack, '<Q')
pack_long = functools.partial(struct.pack, '<L')

# global value
# generate scalar on operand and its address pairs
SCALAR_ADDR_PAIRS = {inst.getScalar(1).getValue(): inst.getAddress() for inst in filter(has_scalar_operand, get_all_instructions())}


class NonSparseConst:
    BYTE = 'B'
    LONG = 'L'
    LONGLONG = 'Q'

    def __init__(self, const):
        self._const = const
        self.algorithm = const['algorithm']
        self.name = const['name']
        self.size = const['size']
        self.array = const['array']
        self._byte_array = None

    def handle_byte(self):
        return self.array

    def handle_long(self):
        return ''.join(map(pack_long, self.array))

    def handle_longlong(self):
        return ''.join(map(pack_longlong, self.array))

    def to_bytes(self):
        handler = {
            self.BYTE: self.handle_byte,
            self.LONG: self.handle_long,
            self.LONGLONG: self.handle_longlong
            # if there'll be another types, add handler here
        }.get(self.size)

        if handler is None:
            raise ValueError('{} is not supported'.format(self.size))
        
        return bytes(bytearray(handler()))

    @property
    def byte_array(self):
        if self._byte_array is None:
            self._byte_array = self.to_bytes()
        return self._byte_array


class SparseConst:
    def __init__(self, const):
        self._const = const
        self.algorithm = const['algorithm']
        self.name = const['name']
        self.array = const['array']


class OperandConst:
    def __init__(self, const):
        self._const = const
        self.algorithm = const['algorithm']
        self.name = const['name']
        self.value = const['value']


def find_crypt_non_sparse_consts(names, algs, addrs):
    # print('[*] processing non-sparse consts')
    for nsc in map(NonSparseConst, const.non_sparse_consts):
        found = find(nsc.byte_array)
        if found:
            names.append(nsc.name)
            algs.append(nsc.algorithm)
            addrs.append(found)
            # print(' [+] found {name} for {alg} at {addr}'.format(name=nsc.name, alg=nsc.algorithm, addr=found))
            create_label(found, nsc.name)
    return names, algs, addrs

def find_crypt_sparse_consts(names, algs, addrs):
    # print('[*] processing sparse consts')

    for sc in map(SparseConst, const.sparse_consts):
        # get address of first const matched one in operands 
        found_addr = SCALAR_ADDR_PAIRS.get(sc.array[0])
        if found_addr:
            # check the rest of consts, maybe it should be in the same function
            # it is noted that it will be failed if the constants are not used in function (like shellcode).
            maybe_crypto_func = get_function_containing(found_addr)
            insts = get_instructions_in_func(maybe_crypto_func)

            # get all scalars in same function
            insts_with_scalars = filter(has_scalar_operand, insts)
            scalars = [inst.getScalar(1).getValue() for inst in insts_with_scalars]

            # check all values in consts array are contained in scalars in same function 
            if all([c in scalars for c in sc.array]):
                # if all consts are contained
                # add comment at the first found const's address
                names.append(sc.name)
                algs.append(sc.algorithm)
                addrs.append(found_addr)
                # print(' [+] found {name} for {alg} at {addr}'.format(name=sc.name, alg=sc.algorithm, addr=found_addr))
                create_label(found_addr, sc.name)
    return names, algs, addrs

def find_crypt_operand_consts(names, algs, addrs):
    # print('[*] processing operand consts')
    for oc in map(OperandConst, const.operand_consts):
        found_addr = SCALAR_ADDR_PAIRS.get(oc.value)
        if found_addr:
            names.append(oc.name)
            algs.append(oc.algorithm)
            addrs.append(found_addr)
            # print(' [+] found {name} for {alg} at {addr}'.format(name=oc.name, alg=oc.algorithm, addr=found_addr))
            set_eol_comment(found_addr, oc.name)
    return names, algs, addrs


def find_check_strs(kws, keywords):
    # print('[*] processing check strings')
    strs = []
    # syms = []
    # kstrs = []


    # Get symbols
    sm = currentProgram.getSymbolTable()
    symbols = sm.getDefinedSymbols()  

    # Check path for calls to crypto funcs, etc
    crypto_syms = []

    # First identify crypto symbols so we don't repeat
    while symbols.hasNext():
        s = symbols.next()
        for cs in keywords:
            if cs in s.getName():
                crypto_syms.append(s)

    symbols = sm.getDefinedSymbols()


    # Now check if refs to crypto symbols in the program
    for s in crypto_syms:
        s_refs = s.getReferences()
        for r in s_refs:
            r_addr = r.getFromAddress()
            if r_addr >= currentProgram.minAddress and r_addr <= currentProgram.maxAddress:
                for cs in keywords:
                    if cs in s.getName():
                        # print(' [+] found {name} for {alg} at {addr}'.format(name=s.getName(), alg=cs, addr=r_addr))
                        strs.append(s.getName()+":"+str(r_addr))
                        # syms.append(s)
    
    for kw in kws:
        keyword = str(kw.toString()).replace('ds "', '').replace('"','')
        references = getReferencesTo(kw.getAddress())
        for r in references:
            r_addr = r.getFromAddress()
            for cs in keywords:
                if cs in keyword and keyword not in strs:
                    # print(' [+] found {name} for {alg} at {addr}'.format(name=keyword, alg=cs, addr=r_addr))
                    strs.append(keyword+":"+str(r_addr))
                    # kstrs.append(kw)

    return strs #, syms, kstrs

# function for find keyword address
def find_keyword_addrs(kws, keywords):
    keyword_addrs = {}
    for keyword in keywords:
        keyword_addrs[keyword] = {}

    # Get symbols
    sm = currentProgram.getSymbolTable()
    symbols = sm.getDefinedSymbols()  

    keyword_syms = []

    # identify whether keywords are in symbols
    while symbols.hasNext():
        s = symbols.next()
        for cs in keywords:
            if cs in s.getName():
                keyword_syms.append(s)

    symbols = sm.getDefinedSymbols()


    # Now check if refs to crypto symbols in the program
    for s in keyword_syms:
        s_refs = s.getReferences()
        for r in s_refs:
            r_addr = r.getFromAddress()
            if r_addr >= currentProgram.minAddress and r_addr <= currentProgram.maxAddress:
                for cs in keywords:
                    if cs in s.getName():
                        keyword_addrs[cs][str(s.getName())] = str(r_addr)
    
    for kw in kws:
        keyword = str(kw.toString()).replace('ds "', '').replace('"','')
        references = getReferencesTo(kw.getAddress())
        for r in references:
            r_addr = r.getFromAddress()
            for cs in keywords:
                if cs in keyword and keyword not in keyword_addrs.keys():
                    keyword_addrs[cs][str(keyword)] = str(r_addr)
                    # kstrs.append(kw)
    return keyword_addrs 

  

def find_crypt():
    names = list()
    algs = list()
    addrs = list()
    # strs = list()
    names, algs, addrs = find_crypt_non_sparse_consts(names, algs, addrs)
    names, algs, addrs = find_crypt_sparse_consts(names, algs, addrs)
    names, algs, addrs = find_crypt_operand_consts(names, algs, addrs)
    # strs = find_crypt_strs(strs)
    return names, algs, addrs#, strs

def find_check(kws):
    checksums = list()
    devices = list()
    versions = list()
    signs = list()
    reboots = list()
    writes = list()
    deliveries = list()

    checksums = find_check_strs(kws, checksumWords)
    devices = find_check_strs(kws, deviceWords)
    versions = find_check_strs(kws, versionWords)
    signs = find_check_strs(kws, signWords)
    reboots = find_check_strs(kws, rebootWords)
    writes = find_check_strs(kws, writeWords)
    deliveries = find_check_strs(kws, deliveryWords)

    return checksums, devices, versions, signs, reboots, writes, deliveries




# Verbosity and scope
DEBUG = False
VERBOSE = False
VVERBOSE  = False # False

# Sinks
cf_sinks = ['system', '___system', 'bstar_system', 'popen',
         'doSystemCmd', 'doShell', 'twsystem', 'CsteSystem', 'cgi_deal_popen',
         'ExeCmd', 'ExecShell', 'exec_shell_popen', 'exec_shell_popen_str',
         'strcpy', 'sprintf', 'memcpy', 'strcat', 'reboot']

exec_sinks = ['system', '___system', 'bstar_system', 'popen',
         'doSystemCmd', 'doShell', 'twsystem', 'CsteSystem', 'cgi_deal_popen',
         'ExeCmd', 'ExecShell', 'exec_shell_popen', 'exec_shell_popen_str',
         'strcpy', 'sprintf', 'memcpy', 'strcat', 'reboot']

# bof_sinks = ['strcpy', 'sprintf', 'memcpy', 'strcat']

# Results file and utilities
global f 
f = None
syms = {}
analyzer = None


def a2h(address):
    return '0x' + str(address)


def getAnalyzer():
    global analyzer
    for a in ClassSearcher.getInstances(ConstantPropagationAnalyzer):
        if a.canAnalyze(currentProgram):
            analyzer = a
            break
    else:
        assert 0


def getCallingArgs(addr, pos):
    if not 0 <= pos <= 3:
        return
    arch = str(currentProgram.language.processor)
    if arch == 'ARM':
        reg = currentProgram.getRegister('r%d' % pos)
    elif arch == 'MIPS':
        if getInstructionAt(addr):
            nextInst = getInstructionAt(addr).next
            if len(nextInst.pcode):  # not NOP
                addr = addr.add(8)
        reg = currentProgram.getRegister('a%d' % pos)
    elif arch == 'x86' and str(currentProgram.language.getProgramCounter()) == 'RIP':
        if pos == 3:
            return
        reg = currentProgram.getRegister(['RDI', 'RSI', 'RDX'][pos])
    else:
        return
    return getRegister(addr, reg)


def getRegister(addr, reg):
    if analyzer is None:
        getAnalyzer()

    func = getFunctionContaining(addr)
    if func is None:
        return

    if func in syms:
        symEval = syms[func]
    else:
        symEval = SymbolicPropogator(currentProgram)
        symEval.setParamRefCheck(True)
        symEval.setReturnRefCheck(True)
        symEval.setStoredRefCheck(True)
        analyzer.flowConstants(currentProgram, func.entryPoint, func.body, symEval, monitor)
        syms[func] = symEval

    return symEval.getRegisterValue(addr, reg)


def getStr(addr):
    ad = addr
    ret = ''
    try:
        while not ret.endswith('\0'):
            ret += chr(getByte(ad) % 256)
            ad = ad.add(1)
    except MemoryAccessException:
        return
    return ret[:-1]


def getStrArg(addr, argpos=0):
    rv = getCallingArgs(addr, argpos)
    if rv is None:
        return
    return getStr(toAddr(rv.value))


# Customized function for reboot check 
def checkReboot(addr, argpos=0):
    arg = getStrArg(addr, argpos)
    if arg is not None:
        if "reboot" in arg:
            return True
    return False


def checkConstantStr(addr, argpos=0):
    # empty string is not considered as constant, for it may be uninitialized global variable
    return bool(getStrArg(addr, argpos))


def checkSafeFormat(addr, offset=0):
    data = getStrArg(addr, offset)
    if data is None:
        return False

    fmtIndex = offset
    for i in range(len(data) - 1):
        if data[i] == '%' and data[i + 1] != '%':
            fmtIndex += 1
            if data[i + 1] == 's':
                if fmtIndex > 3:
                    return False
                if not checkConstantStr(addr, fmtIndex):
                    return False
    return True


def getCallee(inst):
    callee = None
    if len(inst.pcode):
        if inst.pcode[-1].mnemonic == 'CALL':
            callee = getFunctionAt(inst.getOpObjects(0)[0])
        elif inst.pcode[-1].mnemonic == 'CALLIND':
            regval = getRegister(inst.address, inst.getOpObjects(0)[0])
            if regval is not None:
                callee = getFunctionAt(toAddr(regval.value))
    return callee


referenced = set()



def findSinkPath(target_addr, vuln, target=None):

    # Control-flow search has additional checks, different entry point
    def cf_search(start_func):
        bbm = BasicBlockModel(currentProgram)
        all_blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)

        pending = []
        completed = []
        cur_visited_block_path = []
        taint_path_count = 0
        total_path_count = 0

        if VVERBOSE:
            funcs = currentProgram.getFunctionManager().getFunctions(True)
            # print_funcs(funcs)

        # Get symbols
        sm = currentProgram.getSymbolTable()
        symbols = sm.getDefinedSymbols()

        # Find main first
        block = all_blocks.next()
        while all_blocks.hasNext() and block.getName() != 'main':
            block = all_blocks.next()

        # Get first function, then get that block
        if block.getName() != 'main':
            first_func_addr = getFirstFunction().getBody().getMinAddress()
            block = bbm.getCodeBlocksContaining(first_func_addr, TaskMonitor.DUMMY)[0]
            if DEBUG:
                print("\t!!! Could not find main !!!\n\t! Starting from first function !\n")

        # DFS analysis
        flow = [[block.getName(), block.getMinAddress(), block.getFlowType()]]
        while block:
            # Keep track of completed blocks
            completed.append(block)

            if VERBOSE:
                print("\t===BLOCK===")
                print("\tLabel: {}".format(block.getName()))
                print("\tMin Address: {}".format(block.getMinAddress()))
                print("\tMax address: {}".format(block.getMaxAddress()))
                print("\tFlow Type: {}\n".format(block.getFlowType()))
            if VVERBOSE:
                print("\t===DIS===")
                print_disassembly(block)
                # inst = getInstructionAt(block.getMinAddress())
                # if inst:
                #     callee = getCallee(inst)
                #     print(callee)
            
            dests = block.getDestinations(TaskMonitor.DUMMY)

            # Check if block is a sink, if so we found a path from source to sink, stop
            if block.getName() in cf_sinks: # and checkReboot(block.getMinAddress())) or block.getName()=="reboot"
                if DEBUG:
                    print("\t===VULN===")
                    print('\t' + block.getName())
                    
                # Check symbol table for symbol references in this block
                while symbols.hasNext():
                    s = symbols.next()
                    s_refs = s.getReferences()
                    for r in s_refs:
                        r_addr =r.getFromAddress()
                        if r_addr >= block.getMinAddress() and r_addr <= block.getMaxAddress():
                            if DEBUG:
                                print('\t' + str(s) + " referenced in vulnerable block")
                                print('\tRef Address: ' + str(r_addr))
                symbols = sm.getDefinedSymbols()

                total_path_count += 1

            else:
                # This part does the DFS by getting next unvisited child block, explore next
                # If no new destination blocks, we will backtrack
                while dests.hasNext():
                    d = dests.next()
                    d_block = d.getDestinationBlock()
                    if d_block.getName() in cf_sinks or d_block not in completed:
                        pending.append(d_block)
                        # Update current path
                        flow.append([d_block.getName(), d_block.getMinAddress(), d_block.getFlowType()])
                        # If a sink we stop searching down the tree, so don't add this block to current path
                        if d_block.getName() not in cf_sinks:
                            cur_visited_block_path.append(block)
                        break
            
            if pending:
                # Found child, continue down
                block = pending.pop()
            else:
                # No unvisited child, so check if we can backtrack up tree
                if cur_visited_block_path:
                    block = cur_visited_block_path.pop()
                    flow.pop()
                else:
                    # Back to root, done
                    block = None

        if VVERBOSE:
            with open("symbol_table.txt", 'w') as st:
                print >>st, 'SYMBOL TABLE'
                while symbols.hasNext():
                    s = symbols.next()
                    print >>st, "Symbol: ", str(s)
            
        return taint_path_count, total_path_count

    # Keyword search starts at kw ref, simply looks for path
    def kw_search(start_func, vuln):
        bbm = BasicBlockModel(currentProgram)
        block = bbm.getCodeBlocksContaining(start_func, TaskMonitor.DUMMY)[0]

        pending = []
        completed = []
        cur_visited_block_path = []


        if vuln == 'taint_analysis':
            sinks = exec_sinks

        # DFS analysis
        flow = [[block.getName(), block.getMinAddress(), block.getFlowType()]]
        while block:
            # Keep track of completed blocks
            completed.append(block)

            if VERBOSE:
                print("\t===BLOCK===")
                print("\tLabel: {}".format(block.getName()))
                print("\tMin Address: {}".format(block.getMinAddress()))
                print("\tMax address: {}".format(block.getMaxAddress()))
                print("\tFlow Type: {}\n".format(block.getFlowType()))
            if VVERBOSE:
                print("\t===DIS===")
                print_disassembly(block)
                print('')
            
            dests = block.getDestinations(TaskMonitor.DUMMY)

            # Check if block is a sink, if so we found a path from source to sink, stop
            if block.getName() in cf_sinks: # and checkReboot(block.getMinAddress())) or block.getName()=="reboot"
                if DEBUG:
                    print("\t===VULN===")
                    print('\t' + block.getName())

                # if f is not None:
                #     if target:
                #         print >>f, 'Target: ', target, ' @ ', start_func
                #     else:
                #         print >>f, 'IPC @ ', start_func
                # print_path_to_file(flow)

                return flow[-1][0]
            else:
                # This part does the DFS by getting next unvisited child block, explore next
                # If no new destination blocks, we will backtrack
                while dests.hasNext():
                    d = dests.next()
                    d_block = d.getDestinationBlock()
                    if d_block.getName() in sinks or d_block not in completed:
                        pending.append(d_block)
                        # Update current path
                        flow.append([d_block.getName(), d_block.getMinAddress(), d_block.getFlowType()])
                        # print([d_block.getName(), d_block.getMinAddress(), d_block.getFlowType()])
                        # If a sink we stop searching down the tree, so don't add this block to current path
                        if d_block.getName() not in sinks:
                            cur_visited_block_path.append(block)
                        break
            
            if pending:
                # Found child, continue down
                block = pending.pop()
            else:
                # No unvisited child, so check if we can backtrack up tree
                if cur_visited_block_path:
                    block = cur_visited_block_path.pop()
                    flow.pop()
                else:
                    # Back to root, done
                    block = None
            
        return None

    def print_path_to_file(path):
        if f is not None:
            print >>f, '[Path to sink: \n\t(>> block name : block addr : flow type)'
            for i in range(len(path)):
                b_name, b_addr, flow_type = path[i]
                print >>f, '\t>>', b_name, '\t: ', a2h(b_addr), '\t: ', flow_type
            print >>f, ']\n'


    def print_disassembly(block):
        listing = currentProgram.getListing()
        insns = listing.getInstructions(block, True)

        while insns.hasNext():
            ins = insns.next()
            print("\t{} {}".format(ins.getAddressString(False, True), ins))


    def print_funcs(func_it):
        while func_it.hasNext():
            f1 = func_it.next()
            print("Function Name",f1.getName())
            print("Function Body" , f1.getBody())
            print("Function Entry" , f1.getEntryPoint())
            print("Functions Calls",f1.getCalledFunctions(TaskMonitor.DUMMY))
            print("Function is Called From",f1.getCallingFunctions(TaskMonitor.DUMMY))
            print('')

    # Determine which search to run
    if vuln == 'control_flow':
        start_func = getFunctionContaining(target_addr)
        return cf_search(start_func)
    elif vuln == 'taint_analysis':
        # Find entry points for each kw ref
        # If no target then searching IPC, target_addr is already correct
        if target:
            cur_addr = find(target_addr, target)
        else:
            cur_addr = target_addr
        target_found = False
        target_list = []
        vuln_path_found = 0 #False
        if cur_addr:
            target_found = True
        searched_addrs = []

        # Find each occurrence of target, check if vuln path, stop if there is
        if target:
            # print("target: " + target)
            # print("cur_addr: " + a2h(cur_addr))
            while target_found and cur_addr < currentProgram.maxAddress and cur_addr not in searched_addrs: #and not vuln_path_found
                searched_addrs.append(cur_addr)
                refs = getReferencesTo(cur_addr)
                # Run search on each ref/entry point
                for r in refs:
                    # print("ref: " + a2h(r.getFromAddress()))
                    end_func = kw_search(r.getFromAddress(), vuln)
                    if end_func:
                        vuln_path_found = vuln_path_found + 1#True
                        target_list.append(str(getDataContaining(cur_addr).toString()).replace('ds "', '').replace('"','') \
                        + ": " + a2h(r.getFromAddress())+": " + end_func)
                        # break
                
                cur_addr = cur_addr.add(1)
                cur_addr = find(cur_addr, target)
                if not cur_addr:
                    break
                # print("cur_addr: " + a2h(cur_addr))
        else:
            # IPC, just search the one address
            searched_addrs.append(cur_addr)
            end_func = kw_search(r.getFromAddress(), vuln)
            if end_func:
                vuln_path_found = vuln_path_found + 1#True
                target_list.append(str(getDataContaining(cur_addr).toString()).replace('ds "', '').replace('"','') \
                + ": " + a2h(r.getFromAddress())+": " + end_func)

        if DEBUG:
            if target:
                print("\nFound Target: " + str(target) + "? " + str(target_found))
            else:
                print("\nIPC searched @ " + str(cur_addr))
            print("Path Found? " + str(vuln_path_found))
            print('')
        return vuln_path_found, target_list



def check_files(rootpath, fwresults, fps):
    traverse_path = os.path.join(fwresults, "traverse.json")
    with open(traverse_path, "r") as f:
        files = json.load(f)
    htmls = files['html']
    shs = files['sh']
    elfs = files['elf']

    html_list = []
    sh_list = []
    elf_list = []
    module_list = []
    filtered_fps = []

    # for filepath in fps:
    for filepath in fps:
        original_fp = filepath
        try:
            idx = [path.split("/")[-1] for path in htmls].index(filepath.split("/")[-1])
            if filepath[0] == "/":
                filepath = filepath[1:]
                filepath = os.path.join(rootpath, filepath)
            if filepath not in html_list:
                html_list.append(htmls[idx])
                filtered_fps.append(original_fp)
            continue
        except ValueError:
            pass

        try: 
            idx = [path.split("/")[-1] for path in shs].index(filepath.split("/")[-1])
            if filepath[0] == "/":
                filepath = filepath[1:]
                filepath = os.path.join(rootpath, filepath)
            if filepath not in sh_list:
                sh_list.append(shs[idx])
                filtered_fps.append(original_fp)
            continue
        except ValueError:
            pass

        try:
            idx = [path.split("/")[-1] for path in elfs].index(filepath.split("/")[-1])
            if filepath[0] == "/":
                filepath = filepath[1:]
                filepath = os.path.join(rootpath, filepath)
            if (".so" in filepath or ".ko" in filepath) and filepath not in module_list:
                module_list.append(elfs[idx])
                filtered_fps.append(original_fp)
            elif filepath not in elf_list:
                elf_list.append(elfs[idx])
                filtered_fps.append(original_fp)
            continue    
        except ValueError:
            pass

    
    return list(set(html_list)), list(set(sh_list)), list(set(elf_list)), list(set(module_list)), list(set(filtered_fps))


def run_analysis():
    args = getScriptArgs()
    with open(args[0], 'r') as f:
        results = json.load(f)
    path = currentProgram.getExecutablePath()
    if path in list(results.keys()):
        return
    
    f = open(args[0], 'w')
    rootpath = args[1]
    fwresults = args[2]
    # keywords to search
    keywords = args[3].strip('[]').split(',')
    
    results[path] = {}

    # find IPC
    kws, fps, fp_addrs = find_IPC()

    # find crypts
    # names, algs, addrs = find_crypt()
    checksums, devices, versions, signs, reboots, writes, deliveries = find_check(kws)
    # identify the addresses of reboots
    reboot_addrs = find_keyword_addrs(kws, rebootWords)
    # identify the addresses of IPC keywords
    keyword_addrs = find_keyword_addrs(kws, keywords)
    


    t = time.time()

    reboot_total = 0
    mtd_total = 0
    # delivery_total = 0
    reboots_cmdi = []
    mtds = []
    # deliveries = []
    

    if reboots == list() and writes == list():
        taint_path_count, total_path_count = findSinkPath(currentProgram.minAddress, 'control_flow')
    elif reboots != list():
        # Check each keyword for reboot
        for i, param in enumerate(reboots):
            reboot_num, reboot_list = findSinkPath(currentProgram.minAddress, 'taint_analysis', param)
            reboot_total = reboot_total + reboot_num
            reboots_cmdi  = reboots_cmdi + reboot_list

    elif writes != list():
        # Check each keyword for mtd
        for i, param in enumerate(writes):
            mtd_num, mtd_list = findSinkPath(currentProgram.minAddress, 'taint_analysis', param)
            mtd_total = mtd_total + mtd_num
            mtds = mtds + mtd_list

    kws_list = []
    for kw in kws:
        keyword = str(kw.toString()).replace('ds "', '').replace('"','')
        kws_list.append(keyword)

    results[path]['para'] = kws_list
    htmls, shs, elfs, modules, filtered_fps = check_files(rootpath, fwresults, fps)
    filtered_fp_addrs = {key: value for key, value in fp_addrs.items() if key in filtered_fps}
    
    results[path]['call'] = {}
    results[path]['call']['html'] = htmls
    results[path]['call']['sh'] = shs
    results[path]['call']['elf'] = elfs
    results[path]['module'] = modules

    # results[path]['crypt'] = list(set(algs))
    
    results[path]['reboot'] = reboots
    results[path]['write'] = writes
    results[path]['delivery'] = deliveries

    results[path]['checksum'] = checksums
    results[path]['device'] = devices
    results[path]['version'] = versions
    results[path]['signature'] = signs
    
    # include the addresses of IPC keywords
    results[path]['ipc'] = keyword_addrs
    results[path]['invocation'] = filtered_fp_addrs

    if f is not None:
        # print(results)
        json.dump(results, f)
        f.close()
        
    t = time.time() - t
    # print('Time Elapsed:' + str(t))

    return

if __name__ == '__main__':
    run_analysis()


