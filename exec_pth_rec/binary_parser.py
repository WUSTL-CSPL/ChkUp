import re
from collections import namedtuple
from exec_pth_rec.shell_syntax_parser import check_msg_list
import os
import configs.analysis_config as config
import subprocess
import json

class BinaryParser:

    def ascii_strings(self, buf, ASCII_BYTE, String, n=4):
        reg = rb"([%s]{%d,})" % (ASCII_BYTE, n)
        ascii_re = re.compile(reg)
        for match in ascii_re.finditer(buf):
            yield String(match.group().decode("ascii"), match.start())

    def unicode_strings(self, buf, ASCII_BYTE, String, n=4):
        reg = rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        uni_re = re.compile(reg)
        for match in uni_re.finditer(buf):
            try:
                yield String(match.group().decode("utf-16"), match.start())
            except UnicodeDecodeError:
                pass

    def get_string(self, filepath):
        with open(filepath, 'rb') as f:
            b = f.read()
        strs = []

        ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
        String = namedtuple("String", ["s", "offset"])
        
        for s in self.ascii_strings(b, ASCII_BYTE, String):
            strs.append(s.s)

        for s in self.unicode_strings(b, ASCII_BYTE, String):
            strs.append(s.s)
    
        return strs

    def search_parameter(self, parameters, strs):
        results = set()
        for para in parameters:
            for str in strs:
                if str.lower() == para.lower():
                    results.add(para)
                    break
        return list(results)

    def search_function(self, functions, strs):
        results = set()
        for func in functions:
            func = func.split("/")[-1]
            for str in strs:
                if str.find(func) >= 0:
                    results.add(func)
                    break
        return list(results)

    def search_pattern(self, strs):
        res = []
        results = set()
        pattern1 = re.compile(r"^(?=.*?firmware|fw)(?=.*?upd|upg).+$", re.I|re.M)
        pattern2 = re.compile(r"^(?=.*?ver|check|digest|md5|sha256|sign|cert)(?=.*?firmware|fw).+$", re.I|re.M) 
        for str in strs:
            res = res + pattern1.findall(str)
            res = res + pattern2.findall(str)
        results = set(res)
        return list(results)
    
    def search_msg(self, strs):
        results = set()
        for str in strs:
            for item in check_msg_list:
                if item in str:
                    results.add(item)
        return list(results)
                    
    def parse(self, filepath, parameters=[], functions=[]):
        strs = self.get_string(filepath)
        paras = self.search_parameter(parameters, strs)
        funcs = self.search_function(functions, strs)
        patterns = self.search_pattern(strs)
        msgs = self.search_msg(strs)
        return paras, funcs, patterns, msgs
    
    # Get the binary entry
    def search_entry(self, file_list):
        filepaths = []
        features = []
        results = []
        cluster_results = []

        msg_count = {}
        function_count = {}
        pattern_count = {}
        msg_norm = {}
        function_norm = {}
        pattern_norm = {}
        
        msg_MAX = 0
        msg_MIN = 9999
        msg_NORM_MAX = 0
        msg_NORM_MIN = 9999
        msg_MAX_SH = ""
        function_MAX = 0
        function_MIN = 9999
        function_NORM_MAX = 0
        function_NORM_MIN = 9999
        function_MAX_SH = ""
        pattern_MAX = 0
        pattern_MIN = 9999
        pattern_NORM_MAX = 0
        pattern_NORM_MIN = 9999
        pattern_MAX_SH = ""

        filename_pattern = re.compile(r"^(?=.*?(firmware|fw|sys))(?=.*?(upd|upg|ftp|check|upgrade|update)).+$", re.I|re.M)

        for filepath in file_list:

            if not filepath.split("/")[-1]:
                filename = filepath.split("/")[-2]
            else:
                filename = filepath.split("/")[-1]

            if filepath in filepaths or filepath in results or ".so" in filepath or ".ko" in filepath:
                continue

            paras, funcs, patterns, msgs = self.parse(filepath)
            
            # the total number of num_paras and num_funcs can represent the number of varialbe and function name pattern
            num_paras = len(paras)
            num_funcs = len(funcs)
            num_patterns = len(patterns)
            num_msgs = len(msgs)

            if len(filename_pattern.findall(filename))>0:
                results.append(filepath)
                function_count[filepath] = num_paras+num_funcs
                pattern_count[filepath] = num_patterns+len(filename_pattern.findall(filename))   
                msg_count[filepath] = num_msgs
            if not results and num_patterns > 0:
                filepaths.append(filepath)
                features.append(0.3*num_paras+0.3*num_funcs+0.4*num_patterns) #num_patterns
                function_count[filepath] = num_paras+num_funcs
                pattern_count[filepath] = num_patterns   
                msg_count[filepath] = num_msgs   
            
        if features and filepaths:
            features_sorted, cluster_results = zip(*sorted(zip(features, filepaths)))
            cluster_results = list(cluster_results)
            features_sorted = list(features_sorted)
        
        for count, (k, v) in enumerate(msg_count.items()):
            if count == 0:
                msg_MAX = v
                msg_MIN = v
            else:
                if v > msg_MAX:
                    msg_MAX = v
                elif v < msg_MIN:
                    msg_MIN = v
        for count, (k, v) in enumerate(function_count.items()):
            if count == 0:
                function_MAX = v
                function_MIN = v
            else:
                if v > function_MAX:
                    function_MAX = v
                elif v < function_MIN:
                    function_MIN = v

        for count, (k, v) in enumerate(pattern_count.items()):
            if count == 0:
                pattern_MAX = v
                pattern_MIN = v
            else:
                if v > pattern_MAX:
                    pattern_MAX = v
                elif v < pattern_MIN:
                    pattern_MIN = v

        for count, (k, v) in enumerate(msg_count.items()):
            if msg_MAX  == msg_MIN == 0:
                msg_NORM_MAX = 0
                break
            elif msg_MAX == msg_MIN != 0:
                msg_NORM_MAX = 0
                msg_MAX_SH = k
                continue
            norm = (v - msg_MIN) / (msg_MAX - msg_MIN)
            msg_norm[k] = norm
            if count == 0:
                if norm > msg_NORM_MAX:
                    msg_NORM_MAX = norm
                    msg_MAX_SH = k
                elif norm < msg_NORM_MIN:
                    msg_NORM_MIN = norm
            else:
                if norm > msg_NORM_MAX:
                    msg_NORM_MAX = norm
                    msg_MAX_SH = k
                elif norm < msg_NORM_MIN:
                    msg_NORM_MIN = norm

        for count, (k, v) in enumerate(function_count.items()):
            if function_MAX  == function_MIN == 0:
                function_NORM_MAX = 0
                break
            elif function_MAX == function_MIN != 0:
                function_NORM_MAX = 0
                function_MAX_SH = k
                continue
            norm = (v - function_MIN) / (function_MAX - function_MIN)
            function_norm[k] = norm
            if count == 0:
                if norm > function_NORM_MAX:
                    function_NORM_MAX = norm
                    function_MAX_SH = k
                elif norm < function_NORM_MIN:
                    function_NORM_MIN = norm
            else:
                if norm > function_NORM_MAX:
                    function_NORM_MAX = norm
                    function_MAX_SH = k
                elif norm < function_NORM_MIN:
                    function_NORM_MIN = norm
                    
        for count, (k, v) in enumerate(pattern_count.items()):
            if pattern_MAX  == pattern_MIN == 0:
                pattern_NORM_MAX = 0
                break
            elif pattern_MAX == pattern_MIN != 0:
                pattern_NORM_MAX = 0
                pattern_MAX_SH = k
                continue
            norm = (v - pattern_MIN) / (pattern_MAX - pattern_MIN)
            pattern_norm[k] = norm
            if count == 0:
                if norm > pattern_NORM_MAX:
                    pattern_NORM_MAX = norm
                    pattern_MAX_SH = k
                elif norm < pattern_NORM_MIN:
                    pattern_NORM_MIN = norm
            else:
                if norm > pattern_NORM_MAX:
                    pattern_NORM_MAX = norm
                    pattern_MAX_SH = k
                elif norm < pattern_NORM_MIN:
                    pattern_NORM_MIN = norm

        pattern123 = {}

        for k in pattern_norm:
            for k1 in function_norm:
                if k in k1:
                    for k2 in msg_norm:
                        if k1 in k2:
                            pattern123[k] = 0.33 * msg_norm[k2] + 0.33 * function_norm[k1] + 0.33 * pattern_norm[k]
                            break
                    break

        maxPatternSH123 = max(pattern123, key=lambda x: float(pattern123[x]), default=None)
        maxPatternNorm123 = max(pattern123.values(), default=0)

        return maxPatternSH123, maxPatternNorm123

    # get the update handler binary
    def get_binhandler(self, file_list, parameters, functions, elfs):
        elf_dict = {}
        cluster_dict = {}
        filepaths = []
        features = []
        results = []
        cluster_results = []

        for elf in elfs:
            paras, funcs, patterns, msgs = self.parse(elf, parameters, functions)
            elf_dict[elf] = {'para': paras, 'func': funcs, 'pattern': patterns, 'msg': msgs} 

        filename_pattern = re.compile(r"^(?=.*?(firmware|fw))(?=.*?(upd|upg|ftp|check)).+$", re.I|re.M)
        for filepath in file_list:
            if filepath in elfs:
                continue
            filename = filepath.split("/")[-1]

            if filepath in filepaths or filepath in results or ".so" in filepath or ".ko" in filepath:
                continue

            webserver_words = ["httpd", "boa"]
            for server_type in webserver_words:
                if server_type in filepath:
                    results.append(filepath)

            paras, funcs, patterns, msgs = self.parse(filepath, parameters, functions)
            num_paras = len(paras)
            num_funcs = len(funcs)
            num_patterns = len(patterns)

            elf_dict[filepath] = {'para': paras, 'func': funcs, 'pattern': patterns, 'msg': msgs} 
            if parameters == set() and functions == set():
                if len(filename_pattern.findall(filename))>0:
                    results.append(filepath)
                if not results and num_patterns > 0:
                    filepaths.append(filepath)
                    features.append(num_patterns) 
            else:    
                if num_paras > 0 or num_funcs > 0:
                    filepaths.append(filepath)
                    features.append(0.3*num_paras+0.3*num_funcs+0.4*num_patterns)
        
        if features and filepaths:
            features_sorted, cluster_results = zip(*sorted(zip(features, filepaths)))
            cluster_results = [list(cluster_results)[0]]
            features_sorted = [list(features_sorted)[0]]

        final_results = set(cluster_results) | set(results) | set(elfs) 
        cluster_dict = {key:value for key, value in elf_dict.items() if key in final_results}
        return cluster_dict

    # use Ghidra for binary analysis
    def ghidra_analysis(self, filepath, keywords=[]):
        # define ghidra project path
        ghidra_project = os.path.join(config.FW_RESULTS, "ghidra_project")
        if not os.path.isdir(ghidra_project):
            os.makedirs(ghidra_project)
        
        binpath = filepath.strip('\n')
        binname = binpath.split('/')[-1]

        output_name = os.path.join(config.FW_RESULTS, "binaries.json")
        
        project_name = binname 
        ghidra_rep = os.path.join(ghidra_project, binname) + ".rep"
        ghidra_log = os.path.join(ghidra_project, binname) + ".log"

        ghidra_args = [
            config.HEADLESS_GHIDRA, ghidra_project, project_name,
            '-postscript', config.GHIDRA_SCRIPT, output_name, config.ROOT_PATH, config.FW_RESULTS, json.dumps(keywords),
            '-scriptPath', os.path.dirname(config.GHIDRA_SCRIPT)
        ]

        if os.path.exists(ghidra_rep):
            ghidra_args += ['-process', os.path.basename(binpath)]
        else:
            ghidra_args += ['-import', "'" + binpath + "'"]

        with open(ghidra_log, "w") as f:
            p = subprocess.Popen(ghidra_args, stdout=f, stderr=f)
            p.wait()
