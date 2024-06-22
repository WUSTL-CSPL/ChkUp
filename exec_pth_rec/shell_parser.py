import re
from utilities.pth_utils import Utils
from exec_pth_rec.shell_syntax_parser import shell_analysis, check_msg_list


class ShellParser:

    def shell_extractor(self, text):
        parameters = set()
        functions = set()
        content = text.decode('utf-8', 'ignore')

        paras1 = re.findall(r"([a-zA-Z0-9_]+)=", content)
        paras2 = re.findall(r"([a-zA-Z0-9_]+) =", content)
        funcs1 = re.findall(r"([a-zA-Z0-9_]+)\(.*\)", content)
        funcs2 = re.findall(r"([a-zA-Z0-9_]+) \(.*\)", content)

        parameters = parameters | set(paras1) | set(paras2)
        functions = functions | set(funcs1) | set(funcs2)

        parameters = Utils.info_filter(parameters, 1)
        functions = Utils.info_filter(functions, 0)
        return parameters, functions

    
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
        with open(filepath, "rb") as f:
            text = f.read()
            content = text.decode('utf-8', 'ignore')
        lines = content.splitlines()
        sh_parameters, sh_functions = self.shell_extractor(text)
        paras = self.search_parameter(parameters, sh_parameters)
        funcs = self.search_function(functions, sh_functions)
        patterns = self.search_pattern(lines)
        msgs = self.search_msg(lines)
        return paras, funcs, patterns, msgs
    
    # Get the shell entry
    def search_entry(self, file_list):
        shell_dict = {}
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
            if 'language' in filepath:
                continue
            if not filepath.split("/")[-1]:
                filename = filepath.split("/")[-2]
            else:
                filename = filepath.split("/")[-1]

            if filepath in filepaths or filepath in results:
                continue

            paras, funcs, patterns, msgs = self.parse(filepath)
            
            num_paras = len(paras)
            num_funcs = len(funcs)
            num_patterns = len(patterns)
            num_msgs = len(msgs)

            shell_dict[filepath] = {'para': paras, 'func': funcs}

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
        
        if len(set(results)) == 1 and list(set(results))[0].endswith('sysupgrade'):
            final_results = set(results)
        else:
            final_results = set(cluster_results) | set(results)

        for filepath in final_results:
            msg_count[filepath] = 0
            analysis_results = shell_analysis(filepath, None)
            for block in analysis_results[filepath]:
                if block == "metadata":
                    continue
                else:
                    functypes = ['delivery', 'checksum', 'device', 'version', 'signature', 'reboot', 'write']
                    for functype in functypes:
                        pattern_count[filepath] = pattern_count[filepath] + len(analysis_results[filepath][block][functype])

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

        maxPatternSH123 = max(list(pattern123.keys()), key=lambda k: pattern123[k], default=None)
        maxPatternNorm123 = max(pattern123.values(), default=0)

        return maxPatternSH123, maxPatternNorm123


    # Get the update handler binary
    def get_shellhandler(self, file_list, parameters, functions, shs):
        shell_dict = {}
        cluster_dict = {}
        filepaths = []
        features = []
        results = []
        cluster_results = []

        for sh in shs:
            paras, funcs, patterns, msgs = self.parse(sh, parameters, functions)
            shell_dict[sh] = {'para': paras, 'func': funcs, 'pattern': patterns, 'msg': msgs} 


        filename_pattern = re.compile(r"^(?=.*?(firmware|fw|sys))(?=.*?(upd|upg|ftp|check|upgrade|update)).+$", re.I|re.M)
        for filepath in file_list:
            if filepath in shs or 'language' in filepath:
                continue
            filename = filepath.split("/")[-1]

            if filepath in filepaths or filepath in results:
                continue

            paras, funcs, patterns, msgs = self.parse(filepath, parameters, functions)
            num_paras = len(paras)
            num_funcs = len(funcs)
            num_patterns = len(patterns)

            shell_dict[filepath] = {'para': paras, 'func': funcs, 'pattern': patterns, 'msg': msgs} 
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
        

        if len(set(results)) == 1 and list(set(results))[0].endswith('sysupgrade'):
            final_results = set(results)
        else:
            final_results = set(cluster_results) | set(results) | shs


        cluster_dict = {key:value for key, value in shell_dict.items() if key in final_results}
        return cluster_dict
