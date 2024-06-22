import os
import re
import json
import collections
from pyparsing import *
import copy
import configs.analysis_config as config


# ----------SHELL-RELATED KEYWORDS------------
shellbuiltInWords = ['alias', 'bg', 'bind',  'builtin', 'caller', 'cd', 'compgen', 'complete', 'compopt',  'declare',\
    'dirs', 'disown', 'echo', 'enable', 'exit', 'export', 'false', 'fc', 'fg', 'getopts', 'hash', 'help', 'history', 'jobs', 'kill', 'let', \
        'local', 'logout', 'mapfile', 'popd', 'printf', 'pushd', 'pwd', 'read', 'readarray', 'readonly', 'return', 'set', 'shift', 'shopt', \
            'suspend', 'test', 'times', 'trap', 'true', 'type', 'typeset', 'ulimit', 'umask', 'unalias', 'unset', 'wait']
execCommands = ['command', 'eval', 'exec', 'source']
execPattern = re.compile(r"\.\/.*")

usualCommands = ['cat', 'dd', 'mkdir', 'rmdir', 'rm', '-rf', 'ls', 'ps', 'tree', 'find', 'grep', 'egrep', 'sed', 'awk', 'ifconfig', 'ping', 'rm', 'du', 'df', 'less', 'more', 'test', 'cp', 'sleep', 'chmod', 'mv', 'logger', 'head', 'reboot', 'mtd', 'rcS', 'rc', 'wget', 'sh', 'ssi', 'gunzip', 'lsmod', 'brctl', 'dmesg', 'mount', 'init', 'free_caches', 'echo', 'insmod', 'killall', 'time', 'date', 'ip', 'openssl', 'tc', 'ds', 'igmpproxy', 'rt2860apd', 'rtinicapd', 'ledcontrol', 'syslogd', 'route', 'udhcpc', 'rmmod', 'klogd', 'sysctl', 'datalib', 'crond', 'wc', 'cut', 'hexdump', 'tail', 'tr', 'uniq', 'sort', 'diff', 'cmp', 'tee', 'split', 'comm', 'join', 'nl', 'paste', 'seq', 'shred', 'stat', 'sync', 'touch', 'truncate', 'uptime', 'wc', 'who', 'whoami', 'yes', 'zcat', 'zless', 'zmore', 'zgrep', 'zdiff', 'zcmp', 'zforce', 'zegrep', 'zfgrep', 'zless', 'zmore', 'znew', 'zcat', 'zdiff', 'zgrep', 'zless', 'zmore', 'znew', 'zforce', 'zegrep', 'zfgrep', 'zless', 'zmore', 'znew', 'zforce', 'zegrep', 'zfgrep', 'zless', 'zmore', 'znew', 'zforce', 'zegrep', 'zfgrep', 'zless', 'zmore', 'znew', 'zforce', 'zegrep', 'zfgrep', 'zless', 'zmore', 'znew', 'zforce', 'zegrep', 'zfgrep', 'zless', 'zmore', 'znew', 'zforce', 'zegrep', 'zfgrep', 'zless', 'zmore', 'znew', 'zforce', 'zegrep', 'zfgrep', 'zless', 'zmore', 'znew', 'zforce', 'zegrep', 'zfgrep', 'zless', 'zmore', 'znew', 'zforce', 'zegrep', 'zfgrep', 'printf', 'arping', 'fgrep', 'kill', '[', 'ebtables', 'passwd', 'udhcpd', 'config', 'run-ramfs', 'iptables', 'ip6tables', 'ip6tables-restore', 'ip6tables-save', 'iptables-restore', 'ip', 'iwpriv']
complexWords = ['for', 'if', 'else', 'elif', 'fi', 'do', 'done', 'while', 'case', 'esac', 'until', 'select', 'break', 'continue'] #{,},((,)),[[,]],
brackets= ['(', ')', '{', '}', '[', ']', '((', '))','[[',  ']]','{{'  '}}', '()', '[]', '{}']
includeCommands = ['.', 'include']

explodeFile = ['ar71xx.sh', 'jshn.sh']


# ----------FIRMWARE UPDATE-RELATED KEYWORDS------------
checksumWords = ['checksum', 'md5', 'sha256', 'crc', 'hash', 'md5sum', 'sha256sum', 'cksum']
deviceWords = ['modulename', 'device', 'platform']
versionWords = ['version', 'fwtool']
signWords = ['signature', 'rsasign', 'rsa', 'certificate', 'cert'] #'sign',


# ----------BASH PARSER------------
numCompareWords = ['-eq', '-ge', '-gt', '-le', '-lt', '-ne']
strCompareWords = ['=', '!=', '<', '>', '-n', '-z', '==']
pairs = {
    ")": "(",
    "]": "[",
    "}": "{",
}

pipes=oneOf("> >> 2>&1 | &")
importCommands=oneOf("exec ` $( source")
BashIdentifier=Word(alphanums + "_-/$")    
BashQuote=oneOf("\' \"")
BashNumber=Word(nums+".")
BashString=BashQuote + BashIdentifier + BashQuote
BashPath=BashQuote + Combine(Word(alphanums + " _.-/") | ".." | "." | "\*") + BashQuote # TODO:*
BashFlag=OneOrMore("-") + OneOrMore(alphanums)
BashArgument= BashFlag[...] + BashPath[...] + BashIdentifier[...] 
BashRedirect=oneOf("> >> ") + BashArgument[1,...] 
BashComment=Word("#", alphanums + "-_/$")
BashFlag=Combine(OneOrMore("-") + OneOrMore(alphanums))
BashSimpleCommand=BashIdentifier.setResultsName("command") + BashFlag[...] + BashPath[...] + BashIdentifier[...] +  BashRedirect[...] 
BashCompoundCommand = BashSimpleCommand + (oneOf("&& & || | ;") + BashSimpleCommand)[1,...] 

# Message keywords
check_msg_list = ['incorrect_firmware', 'upg_upgrade_error', 'upg_release_note_3_4', 'current_firmware', 'new_firmware', 'chkupg', 'auto_upg_check', 'auto_upg_seconds', 'upg_md5_check_error', 'auto_update_header', 'info_mark_ver', 'upgrade_head', 'upgrade_select_disk', 'upgrade_mark', 'upgrade_new_version', 'upgrade_upon', 'upgrade_note1', 'upgrade_note2', 'autp_upg_head', 'auto_upg_check_ser', 'auto_upg_90s', 'auto_upg_nowan_head', 'auto_upg_nowan', 'auto_upg_detect', 'auto_upg_start_detect', 'auto_upg_not_display', 'autp_upg_firmware', 'upg_progess', 'upg_find_old', 'wait_upg_head', 'wait_serv', 'wait_serv1',
            'wait_serv2', 'wait_serv3', 'wait_cancel', 'download_confile_fail', 'wait_return', 'wait_new_version', 'no_new_version', 'wait_download', 'upg_download_error', 'upg_upload_error', 'wait_string', 'line_string', 'failure_head', 'old_ver', 'new_ver', 'upload_ver', 'download_image', 'download_image_fail', 'not_img', 'error_module', 'upgrade_1', 'upgrade_2', 'upgrade_3', 'error_firm_reg', 'upgrade_4', 'upgrade_5', 'upgrade_6', 'upgrade_7', 'upgrade_8', 'upgrade_9', 'upgrade_10', 'upgrade_11', 'upgrade_12', 'oldver1', 'oldver2', 'oldver3', 'upgrade_turnoff_auto', 'in_upgrade', 'invalid_filename', 'firm_upgrade', 'The router cannot connect to ASUS server to check for the signature update. After reconnecting to the Internet, go back to this page and click Check to check for the latest signature updates', 'Signature checking ...', 'Signature is up to date', 'Signature update failed', 'Signature is updating', 'Signature update completely', 'The F/W is updating ...<br><br>', 'Please <font color=red><b>DO NOT POWER OFF</b></font> the device.<br><br>', 'And please wait for', "<input type='text' readonly name='WaitInfo' value='150' size='3' style='border-width:0; background-color=#DFDFDF; color:#FF3030; text-align:center'>", 'seconds...', 'Please choose a file to upgrade!', 'The selected file is in wrong format, please select another.', 'Are you sure to upgrade the firmware?', 'The device cannot perform software upgrades via the remote management tool. Please upgrade software from within the LAN.', 'Firmware Version:', 'Hardware Version:', 'Firmware Upgrade', 'Processing...', 'Please wait until system reboots...', 'tf_FWF1', 'tf_msg_FWUgReset', 'tf_really_FWF', '_upgrade_firmw', '_FIRMW_DESC', '_FIRMW_DESC_sub', '_upgrade_firmw', 'Do you want to upgrade Firmware?', "Estimated upgrade time:", "Launching firmware upgrade in", "Invalid firmware file", "0 <firmware file> [<delay>]", "About to run firmware update", "Firmware update file check failed!", "Firmware update file"]

def parseAssignmentStatement(stmt):
    assignmentCommands=oneOf("export alias let local")
    assignmentExpr = ZeroOrMore(assignmentCommands) + BashIdentifier.setResultsName("lhs") + "=" + (BashIdentifier|BashNumber).setResultsName("rhs")
    try:
        tokens = assignmentExpr.parseString(stmt)
        return tokens.lhs
    except ParseException:
        return ""
    
def parseSimpleCommand(stmt):
    try:
        tokens = BashSimpleCommand.parseString(stmt)
        return tokens.command
    except ParseException:
        return ""

def parseCompoundCommand(stmt):
    try:
        tokens = BashCompoundCommand.parseString(stmt)
        return tokens.command
    except ParseException:
        return ""

def parseCommandStatement(stmt):
    assignmentCommands=oneOf("set cd bg fg pushd popd ulimit ls")
    assignmentExpr = OneOrMore(assignmentCommands).setResultsName("lhs") + BashFlag[...] + (BashIdentifier).setResultsName("rhs")
    try:
        tokens = assignmentExpr.parseString(stmt)
        return tokens.lhs + tokens.rhs
    except ParseException:
        return ""

def parseInlineComments(stmt):
    assignmentCommands=oneOf("#")
    assignmentExpr = OneOrMore(assignmentCommands).setResultsName("lhs") + BashFlag + (BashIdentifier).setResultsName("rhs")
    try:
        tokens = assignmentExpr.parseString(stmt)
        return tokens.lhs + tokens.rhs
    except ParseException:
        return ""


class BashParser:
    def __init__(self):
        self.line=""

    def parse(self, cmdString):
        cmdString=cmdString.split("#")[0].strip().lower()
        cmd=None
        runCommand=cmdString.split(" ")[0].lower()

        if ( "()" in cmdString or "function " in cmdString): 
            cmd=BashFunction(cmdString)
            return cmd
        # if and loop
        elif runCommand in complexWords: 
            cmd=CompoundCommand(cmdString)
            return cmd
        # usual commands
        elif runCommand in usualCommands:
            cmd=UsualCommand(cmdString)
            return cmd
        # shell buildin words
        elif runCommand in shellbuiltInWords:
            cmd=BuiltinCommand(cmdString)
            return cmd
        # variable assignment
        elif "=" in cmdString: #and ("==" not in cmdString))
            cmd=AssignmentCommand(cmdString)
            return cmd
        # import dependency
        elif runCommand in includeCommands and '$' not in cmdString:
            cmd=DependencyInclusion(cmdString)
            return cmd
        # brackets
        elif runCommand in brackets:
            cmd=BasicBracket(cmdString)
            return cmd
        # exec command
        elif runCommand in execCommands or execPattern.findall(runCommand):
            cmd=ExecCommand(cmdString)
            return cmd
        # self-defined function and other command
        else:
            cmd=BashCommand(cmdString)
            return cmd

class BasicBracket:
    def __init__(self, cmdString):
        self.cmdString = cmdString
        self.cmd = cmdString
        self.cmdType = "BRACKET"

class DependencyInclusion:
    def __init__(self, cmdString):
        self.cmdString = cmdString
        self.cmd=cmdString.split(" ")[0]
        self.para = cmdString.split(" ")[1:]
        self.cmdType="DEPENDENCY"
     
class BashCommand:
    def __init__(self, cmdString):
        self.cmdString = cmdString
        self.cmd=cmdString.split(" ")[0]
        self.para = cmdString.split(" ")[1:]
        self.cmdType="OTHER"

    def setCall(self):
        self.cmdType="CALL"

class ExecCommand:
    def __init__(self, cmdString):
        self.cmdString = cmdString
        if cmdString[0] == '.':
            self.cmd='.'
            self.para = cmdString[1:]
        else:
            self.cmd = cmdString.split(" ", 1)[0]
            self.para = cmdString.split(" ", 1)[1]
        self.cmdType="EXEC"

    def isBuiltin():
        return True

class AssignmentCommand:
    def __init__(self, cmdString):
        self.cmdString = cmdString
        self.cmd = cmdString.split("=")[0].strip()
        self.para = cmdString.split("=")[1].strip()
        self.cmdType="SET"

    def isBuiltin():
        return True
        
class BuiltinCommand (BashCommand):
    def __init__(self, cmdString):
        super(BuiltinCommand, self).__init__(cmdString)
        self.cmdType="BUILTIN"

    def isBuiltin():
        return True

class UsualCommand (BashCommand):
    def __init__(self, cmdString):
        super(UsualCommand, self).__init__(cmdString)
        self.cmdType="USUAL"

    def isBuiltin():
        return False
        
class PipelineCommand (BashCommand):
    def __init__(self, cmdString):
        super(PipelineCommand, self).__init__(cmdString)
        self.cmdType="PIPELINE"
        self.leftCmd=cmdString
        self.rightCmd=cmdString
        print(cmdString)
        
class ListCommand (BashCommand):
    def __init__(self, cmdString):
        super(ListCommand, self).__init__(cmdString)
        self.cmd=cmdString.split(" ")[0]

class CompoundCommand (): 
    def __init__(self, cmdString):
        self.cmdString = cmdString
        self.cmd=cmdString.split(" ")[0]  
        self.para = cmdString.split(" ")[1:]
        if "if" in self.cmdString: 
            self.cmdType="IF"
        elif "fi" in self.cmdString:
            self.cmdType="FI"
        elif "elif" in self.cmdString:
            self.cmdType="ELIF"
        elif "else" in self.cmdString:
            self.cmdType="ELSE"
        elif "for" in self.cmdString:
            self.cmdType="FOR"
        elif "while" in self.cmdString:
            self.cmdType="WHILE"
        elif "until" in self.cmdString:
            self.cmdType="UNTIL"
        elif "done" in self.cmdString:
            self.cmdType="DONE"
        elif "case" in self.cmdString:
            self.cmdType="CASE"
        elif "esac" in self.cmdString:
            self.cmdType="ESAC"
        elif "continue" in self.cmdString:
            self.cmdType="CONTINUE" 
        elif "break" in self.cmdString:
            self.cmdType="BREAK"
        else:
            self.cmdType="LOOP"

    def ifChecker(self):
        cmd = self.para
        variables = []
        for item in list(enumerate(cmd)):
            if item[1] in numCompareWords or item[1] in strCompareWords:
                if item[0]-1 >= 0:
                    variables.append(cmd[item[0]-1])
                if item[0]+1 <= len(cmd)-1:
                    variables.append(cmd[item[0]+1])

        if variables:
            variableTmp = [item.split("_") for item in variables]
            variables = [x for sublist in variableTmp for x in sublist]
            if any(''.join(filter(str.isalnum, item)) in checksumWords for item in variables):
                return 1
            elif any(''.join(filter(str.isalnum, item)) in deviceWords for item in variables):
                return 2
            elif any(''.join(filter(str.isalnum, item))  in versionWords for item in variables):
                return 3
            elif any(''.join(filter(str.isalnum, item))  in signWords for item in variables):
                return 4
        return -1


class BashFunction: 
    def __init__(self, cmdString):
        self.cmdString = cmdString
        self.cmd=cmdString.replace("function","").split("(")[0]
        self.cmdType="FUNCTION"
        self.commandsInBlock=[]

class BasicBlock:
    def __init__(self, cmdString, blockType):
        self.name = cmdString
        self.blockType = blockType
        self.cmdSet = []
        self.dependencies = {}

        self.exterCalls = []
        self.interCalls = []
        self.calls = []

        self.execCommands = []

        self.checksum = []
        self.model = []
        self.version = []
        self.signature = []
        self.mtd = []
        self.reboot = []
        self.delivery = []
        
        self.filePaths = []
    
    def addContents(self, cmdClass):
        self.cmdSet.append(cmdClass)

    def addDependencies(self, deps):
        for item in deps:
            self.dependencies[item] = []
    
    def addExterCalls(self, cmdClass):
        self.exterCalls.append(cmdClass.cmd)
    
    def addInterCalls(self, cmdClass):
        self.interCalls.append(cmdClass.cmd)
    
    def addCalls(self, cmdClass):
        self.calls.append(cmdClass)

    def addExecCommands(self, cmdClass):
        self.execCommands.append(cmdClass.cmdString)

    def addChecksum(self, cmdClass):
        self.checksum.append(cmdClass.cmdString)

    def addModel(self, cmdClass):
        self.model.append(cmdClass.cmdString)
    
    def addVersion(self, cmdClass):
        self.version.append(cmdClass.cmdString)

    def addSignature(self, cmdClass):
        self.signature.append(cmdClass.cmdString)

    def addReboot(self, cmdClass):
        self.reboot.append(cmdClass.cmdString)
    
    def addMtd(self, cmdClass):
        self.mtd.append(cmdClass.cmdString)

    def addDelivery(self, cmdClass):
        self.delivery.append(cmdClass.cmdString)    

    def addFilePaths(self, filePaths):
        self.filePaths = self.filePaths + filePaths

    def removeFilePaths(self, filePaths):
        self.filePaths = list(set(self.filePaths) - set(filePaths)) 

def Grammar(bashCommand):
    SingleQuoteRegEx='(\\\'.*?\\\')'
    DoubleQuoteRegEx='(\\\".*?\\\")'
    VariableRegEx='\$[\{].*?[\}]'
    BackQuoteRegEx='(`).*?(`)'
    SubShellRegEx='($\().*?(\))'
    TestCmdRegEx='($\[\[).*?(\]\])'
    Test2CmdRegEx='($\[).*?(\])'
    Others='.*?'
    Paths = r'((?:[A-Z]:|(?<![:/])[\/]|\~[\/]|(?:\.{1,2}[\/])+)[\w+\s_\-\(\)\/]*(?:\.\w+)*)'

    pattern = re.compile(Paths)
    filePaths = pattern.findall(bashCommand)

    return bashCommand, filePaths

def readScriptFile(filePath):
    with open(filePath,"r") as fileObj:
        content = fileObj.readlines()
    content = [line.strip() for line in content if (re.search("^[\s+]*#",line)==None) and (re.match(r'^\s*$', line)==None)]  
    return content

def generalParser(currentCmd, calls, execs, block, checks, shs):
    Paths = r'((?:[A-Z]:|(?<![:/])[\/]|\~[\/]|(?:\.{1,2}[\/])+)[\w+\s_\-\(\)\/]*(?:\.\w+)*)'
    pattern = re.compile(Paths)
    filePaths = pattern.findall(currentCmd.cmdString)
    filePaths = [path.strip().strip("'").strip('"') for path in filePaths]
    block.addFilePaths(filePaths)
    block.addContents(currentCmd)
    deps = set()
    end = 0

    if currentCmd.cmdType == "DEPENDENCY":
        deps_list = []
        for dep in currentCmd.para:
            if dep[0] == "/":
                dep = dep[1:]
            dep_path = os.path.join(config.ROOT_PATH, dep)
            deps_list.append(dep_path)
        deps = set(deps_list)
        block.addDependencies(deps)
        block.removeFilePaths(list(deps))
    elif currentCmd.cmdType == "IF":
        if currentCmd.ifChecker() == 1: 
            checks[0] = 1
            block.addChecksum(currentCmd)
        elif currentCmd.ifChecker() == 2: 
            checks[1] = 1
            block.addModel(currentCmd)
        elif currentCmd.ifChecker() == 3: 
            checks[2] = 1
            block.addVersion(currentCmd)
        elif currentCmd.ifChecker() == 4: 
            checks[3] = 1
            block.addSignature(currentCmd)
    elif currentCmd.cmdType ==  "USUAL":
        if currentCmd.cmd == "reboot":
            block.addReboot(currentCmd)
        elif currentCmd.cmd == "mtd":
            block.addMtd(currentCmd)
        elif currentCmd.cmd == "wget":
            block.addDelivery(currentCmd)
    elif currentCmd.cmdType == "EXEC":
        flag = 0
        for para in currentCmd.para:
            if 'reboot' in para:
                block.addReboot(currentCmd)
                flag = 1
            if 'mtd' in para:
                block.addMtd(currentCmd)
                flag = 2
            if 'wget' in para:
                block.addDelivery(currentCmd)
                flag = 3
        if flag == 0:
            for para in currentCmd.para:
                execs.append(para)
            block.addExecCommands(currentCmd)
    elif currentCmd.cmd == "cat" and currentCmd.para == ["<<eof"]:
        end = 1
    elif currentCmd.cmdString == "eof":
        end = 0
    elif currentCmd.cmdType == "OTHER":
        calls.append(currentCmd)
        block.addCalls(currentCmd)

    return deps, calls, execs, block, checks, end


def blockParser(stack, currentCmd, calls, execs, block, checks, shs):
    dependencies = set()
    end = 0
    flag = "FUNCBLOCK"
    if currentCmd.cmdType == "BRACKET":
        if currentCmd.cmd in pairs:
            if not stack or stack[-1] != pairs[currentCmd.cmd]:
                pass
            else:
                stack.pop()
        else:
            stack.append(currentCmd.cmd)
        
        if not stack:
            flag = "GENERAL"
    else:
        dependencies, calls, execs, block, checks, end = generalParser(currentCmd, calls, execs, block, checks, shs)
    
    return flag, stack, dependencies, calls, execs, block, checks, end


def shell_analysis(path, callPath):
    lines = readScriptFile(path)
    resultFile = os.path.join(config.FW_RESULTS, "shells.json")

    with open(resultFile, 'r') as fileObj:
        results = json.load(fileObj)
    if path in list(results.keys()):
        return results
    
    results[path] = {}

    traverse_path = os.path.join(config.FW_RESULTS, "traverse.json")
    with open(traverse_path, "r") as f:
        files = json.load(f)
    htmls = files['html']
    shs = files['sh']
    elfs = files['elf']

    flag = "GENERAL"

    dq=collections.deque()

    checks = [0, 0, 0, 0] # Hash, Device, Version, Signature

    functions = set()
    dependencies = set()
    interCalls = set()
    exterCalls = set()
    filePaths = set()
    rebootCalls = set()
    mtdCalls = set()

    calls = []
    execs = []
    blocks = []

    prevcmd=None
    mainBlock = BasicBlock("main", "GENERAL")
    blocks.append(mainBlock)

    for line in lines:
        deps = set()
        bparser = BashParser()
        grammarLine, paths = Grammar(line.strip())
        filePaths = filePaths | set(paths)
        currentCmd=bparser.parse(grammarLine)

        try:
            prevcmd=dq.pop()
        except IndexError:
            prevcmd=None
    
        stack = list()
        if currentCmd.cmdType == "FUNCTION" and "{" in currentCmd.cmdString:
            flag = "FUNCBLOCK"
            functions = functions | set([currentCmd.cmd])
            funcBlock = BasicBlock(currentCmd.cmd, "FUNCBLCOK")
            blocks.append(funcBlock)
            prevcmd = currentCmd
            currentCmd = BasicBracket("{")

        elif prevcmd != None:
            if prevcmd.cmdType == "FUNCTION" and "{" not in prevcmd.cmdString and currentCmd.cmdType == "BRACKET":
                flag = "FUNCBLOCK"
                functions = functions | set([prevcmd.cmd])
                funcBlock = BasicBlock(prevcmd.cmd, "FUNCBLCOK")
                blocks.append(funcBlock)
     
        if flag == "FUNCBLOCK":
            flag, stack, deps, calls, execs, blocks[-1], checks, end = blockParser(stack, currentCmd, calls, execs, blocks[-1], checks, shs)
            if end == 1:
                continue

        elif flag == "GENERAL" and currentCmd.cmdType != "FUNCTION" :
            deps, calls, execs, mainBlock, checks, end = generalParser(currentCmd, calls, execs, blocks[0], checks, shs)
            blocks[0] = mainBlock
            if end == 1:
                continue

        dependencies = dependencies | deps
        dq.append(currentCmd)
    
    for block in blocks:
    # resolve the customized functions calls
        for call in block.calls:
            if call.cmd in functions:
                call.setCall()
                interCalls = interCalls | set([call.cmd])
                block.addInterCalls(call)
                if "/sbin/reboot" in call.cmdString or "/sbin/shutdown" in call.cmdString or call.cmdString=="reboot":
                    block.addReboot(call)
                if 'mtd' in call.cmdString:
                    block.addMtd(call)
                if 'wget' in call.cmdString:
                    block.addDelivery(call)
            else:
                if "/sbin/reboot" in call.cmdString or "/sbin/shutdown" in call.cmdString or call.cmdString=="reboot":
                    block.addReboot(call)
                elif 'mtd' in call.cmdString:
                    block.addMtd(call)
                elif 'wget' in call.cmdString:
                    block.addDelivery(call)
                else:
                    exterCalls = exterCalls | set([call.cmd])
                    block.addExterCalls(call)

    results[path]["metadata"] = {}
    results[path]["metadata"]["callerpath"] = callPath
    results[path]["metadata"]["functions"] = list(functions)
    results[path]["metadata"]["dependencies"] = list(dependencies)

    for block in blocks:
        blockHtml = []
        blockSh = []
        blockElf = []
        for filepath in block.filePaths:
            try:
                idx = [path.split("/")[-1] for path in htmls].index(filepath.split("/")[-1])
                if filepath[0] == "/":
                    filepath = filepath[1:]
                    filepath = os.path.join(config.ROOT_PATH, filepath)
                if filepath not in block.dependencies:
                    blockHtml.append(htmls[idx])
                continue
            except ValueError:
                pass

            try: 
                idx = [path.split("/")[-1] for path in shs].index(filepath.split("/")[-1])
                if filepath[0] == "/":
                    filepath = filepath[1:]
                    filepath = os.path.join(config.ROOT_PATH, filepath)
                if filepath not in block.dependencies:
                    blockSh.append(shs[idx])
                continue
            except ValueError:
                pass

            try:
                idx = [path.split("/")[-1] for path in elfs].index(filepath.split("/")[-1])
                if filepath[0] == "/":
                    filepath = filepath[1:]
                    filepath = os.path.join(config.ROOT_PATH, filepath)
                if filepath not in block.dependencies:
                    blockElf.append(elfs[idx])
                continue    
            except ValueError:
                pass


        for call in block.exterCalls:
            flag = 0
            for filepath in elfs:
                if call == os.path.basename(filepath):
                    flag = 1
                    blockElf.append(filepath)
                    break

            if not flag:
                for filepath in shs:
                    if call == os.path.basename(filepath):
                        flag = 1
                        # print(filepath)
                        blockSh.append(filepath)
                        break

        results[path][block.name] = {}
        results[path][block.name]["depfunctions"] = block.dependencies
        results[path][block.name]["execcommands"] = block.execCommands
        results[path][block.name]["intercalls"] = list(set(block.interCalls))
        results[path][block.name]["extercalls"] = list(set(block.exterCalls))
        results[path][block.name]["checksum"] = block.checksum
        results[path][block.name]["device"] = block.model
        results[path][block.name]["version"] = block.version
        results[path][block.name]["signature"] = block.signature
        results[path][block.name]['reboot'] = block.reboot
        results[path][block.name]['delivery'] = block.delivery
        results[path][block.name]['write'] = block.mtd
        results[path][block.name]["html"] = list(set(blockHtml))
        results[path][block.name]["sh"] = list(set(blockSh))
        results[path][block.name]["elf"] = list(set(blockElf))
    
    with open(resultFile, "w") as fileObj:
        json.dump(results, fileObj)

    return results


def shell_results(path, callPath):
    resultFile = os.path.join(config.FW_RESULTS, "shells.json")
    traverse_path = os.path.join(config.FW_RESULTS, "traverse.json")

    # some file (especially from openwrt) explode in json with lots of blank blocks, we filter those out
    for item in explodeFile:
        if path.endswith(item):
            with open(resultFile, 'r') as fileObj:
                results = json.load(fileObj)
            results[path] = {}
            results[path]['metadata'] = {}
            results[path]['metadata']['callerpath'] = []
            results[path]['metadata']['functions'] = []
            results[path]['metadata']['dependencies'] = []
            results[path]["main"] = {}
            results[path]['main']['depfunctions'] = []
            results[path]['main']['execcommands'] = []
            results[path]['main']['intercalls'] = []
            results[path]['main']['extercalls'] = []
            results[path]['main']['checksum'] = []
            results[path]['main']['device'] = []
            results[path]['main']['version'] = []
            results[path]['main']['signature'] = []
            results[path]['main']['reboot'] = []
            results[path]['main']['write'] = []
            results[path]['main']['delivery'] = []
            results[path]['main']['html'] = []
            results[path]['main']['sh'] = []
            results[path]['main']['elf'] = []
            return results

    results = shell_analysis(path, callPath)

    sh = path
    if results[sh]["metadata"]["dependencies"] != []:
        deps = copy.copy(results[sh]["metadata"]["dependencies"])
        for dep_path in results[sh]["metadata"]["dependencies"]:

            if os.path.isfile(dep_path):
                if dep_path not in list(results.keys()):
                    results = shell_results(dep_path, sh)
            elif os.path.isdir(dep_path):
                deps.remove(dep_path)
                with open(traverse_path, "r") as f:
                    files = json.load(f)
                shells = files['sh']
                for shell in shells:
                    if dep_path in shell:
                        deps.append(shell)
                        if shell not in list(results.keys()):
                            results = shell_results(shell, sh)
            
        # resolve the function call from the dependencies
        for block in list(results[sh].keys()):
            if block != "metadata":
                extercalls = results[sh][block]["extercalls"]
                dep_dict = {}
                for call in extercalls:
                    for dep in deps:
                        if dep in results.keys():
                            if call in results[dep]["metadata"]["functions"]:
                                dep_dict[call] = dep

                for call in list(dep_dict.keys()):
                    if dep_dict[call] not in list(results[sh][block]['depfunctions'].keys()):
                        results[sh][block]['depfunctions'][dep_dict[call]] = []
                    results[sh][block]['extercalls'].remove(call)
                    results[sh][block]['depfunctions'][dep_dict[call]].append(call)

    # sometimes dependencies can be folder, in such case we add each dependencies file under it to sh_results[filepath]['main']['depfunctions']
    for file in results:
        for key in results[file]:
            if key != 'metadata' and key != 'main':
                for deps in results[file][key]['depfunctions']:
                    if deps not in results[file]['main']['depfunctions']:
                        results[file]['main']['depfunctions'][deps] = results[file][key]['depfunctions'][deps]
                    else:
                        results[file]['main']['depfunctions'][deps] = list(set(results[file]['main']['depfunctions'][deps]) | set(results[file][key]['depfunctions'][deps]))
    
    # loop through each function block called, if the block name contains check and a keyword, add such check to check array
    for file in results:
        for key in results[file]:
            if key != 'metadata' and key != 'main':
                for keyword in checksumWords:
                    if 'check' in key and keyword in key:
                        if not 'self' in results[file][key]['checksum']:
                            results[file][key]['checksum'].append('self: {k}'.format(k=key))
                            results[file][key]['checksum'] = list(set(results[file][key]['checksum']))
                for keyword in deviceWords:
                    if 'check' in key and keyword in key:
                        if not 'self' in results[file][key]['device']:
                            results[file][key]['device'].append('self: {k}'.format(k=key))
                            results[file][key]['device'] = list(set(results[file][key]['device']))
                for keyword in versionWords:
                    if 'check' in key and keyword in key:
                        if not 'self' in results[file][key]['version']:
                            results[file][key]['version'].append('self: {k}'.format(k=key))
                            results[file][key]['version'] = list(set(results[file][key]['version']))
                for keyword in signWords:
                    if 'check' in key and keyword in key:
                        if not 'self' in results[file][key]['signature']:
                            results[file][key]['signature'].append('self: {k}'.format(k=key))
                            results[file][key]['signature'] = list(set(results[file][key]['signature']))
    
    # main loop might call hook, add the hook content to internal call 
    content = ''
    with open(path, "rb") as f:
        content = f.read().decode('utf-8', 'ignore')
    hookCalled = re.findall(r'^[ \t]*[^ \t\$\n=]*=[\'\"][^\'\"\$\n=]+[\'\"][ &|\\]*$', content, re.M)
    for entry in hookCalled:
        entry = entry.strip()
        entry = entry.replace('\'', '\"')
        entry = entry.replace(entry.split('\"')[0], '').replace(entry.split('\"')[-1], '').replace('\"', '')
        if entry.isspace() or ':' in entry or '\\' in entry:
            continue
        if ' ' in entry:
            for hookFunc in entry.split(' '):
                results[path]["main"]["extercalls"].append(hookFunc)
                results[path]["main"]["extercalls"] = list(set(results[path]["main"]["extercalls"]))
        else:
            results[path]["main"]["extercalls"].append(entry)
            results[path]["main"]["extercalls"] = list(set(results[path]["main"]["extercalls"]))

    with open(resultFile, "w") as fileObj:
        json.dump(results, fileObj)

    return results
