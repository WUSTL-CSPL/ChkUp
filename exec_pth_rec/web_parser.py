import os
import re
import json
import requests
from utilities.pth_utils import Utils
import configs.analysis_config as config

class WebParser:
    
    def __init__(self):
        pass

    def html_asp_extractor(self, text, filepath):
        web_info = {}

        content = text.decode('utf-8', 'ignore')

        msg_list = set()

        # Message keywords
        check_msg_list = ['incorrect_firmware', 'upg_upgrade_error', 'upg_release_note_3_4', 'current_firmware', 'new_firmware', 'chkupg', 'auto_upg_check', 'auto_upg_seconds', 'upg_md5_check_error', 'auto_update_header', 'info_mark_ver', 'upgrade_head', 'upgrade_select_disk', 'upgrade_mark', 'upgrade_new_version', 'upgrade_upon', 'upgrade_note1', 'upgrade_note2', 'autp_upg_head', 'auto_upg_check_ser', 'auto_upg_90s', 'auto_upg_nowan_head', 'auto_upg_nowan', 'auto_upg_detect', 'auto_upg_start_detect', 'auto_upg_not_display', 'autp_upg_firmware', 'upg_progess', 'upg_find_old', 'wait_upg_head', 'wait_serv', 'wait_serv1',
                    'wait_serv2', 'wait_serv3', 'wait_cancel', 'download_confile_fail', 'wait_return', 'wait_new_version', 'no_new_version', 'wait_download', 'upg_download_error', 'upg_upload_error', 'wait_string', 'line_string', 'failure_head', 'old_ver', 'new_ver', 'upload_ver', 'download_image', 'download_image_fail', 'not_img', 'error_module', 'upgrade_1', 'upgrade_2', 'upgrade_3', 'error_firm_reg', 'upgrade_4', 'upgrade_5', 'upgrade_6', 'upgrade_7', 'upgrade_8', 'upgrade_9', 'upgrade_10', 'upgrade_11', 'upgrade_12', 'oldver1', 'oldver2', 'oldver3', 'upgrade_turnoff_auto', 'in_upgrade', 'invalid_filename', 'firm_upgrade', 'The router cannot connect to ASUS server to check for the signature update. After reconnecting to the Internet, go back to this page and click Check to check for the latest signature updates', 'Signature checking ...', 'Signature is up to date', 'Signature update failed', 'Signature is updating', 'Signature update completely', 'The F/W is updating ...<br><br>', 'Please <font color=red><b>DO NOT POWER OFF</b></font> the device.<br><br>', 'And please wait for', "<input type='text' readonly name='WaitInfo' value='150' size='3' style='border-width:0; background-color=#DFDFDF; color:#FF3030; text-align:center'>", 'seconds...', 'Please choose a file to upgrade!', 'The selected file is in wrong format, please select another.', 'Are you sure to upgrade the firmware?', 'The device cannot perform software upgrades via the remote management tool. Please upgrade software from within the LAN.', 'Firmware Version:', 'Hardware Version:', 'Firmware Upgrade', 'Processing...', 'Please wait until system reboots...', 'tf_FWF1', 'tf_msg_FWUgReset', 'tf_really_FWF', '_upgrade_firmw', '_FIRMW_DESC', '_FIRMW_DESC_sub', '_upgrade_firmw', 'Do you want to upgrade Firmware?', "Firmware update file check failed!", "Estimated upgrade time:", "Launching firmware upgrade in", "Invalid firmware file", "0 <firmware file> [<delay>]", "About to run firmware update", "Firmware update file check failed!", "Firmware update file"]

        contentLines = content.splitlines()
        
        for eachLine in contentLines:
            for item in check_msg_list:
                if item in eachLine:
                    msg_list.add(eachLine)

        # actions: can be cgi implemented by shell or binary
        actions = re.findall(r'(?i)action=[\'\"](.*?)[\'\"]', content)
        actions_lua = re.findall(
            r'(?i)action=[\'\"](.*?)\<\%(.*?)\%\>(.*?)[\'\"]', content)
        actions_set = Utils.info_filter(set(actions), 0)
        actions_lua_set = set()
        for entry in actions_lua:
            luaStr = ''
            for i in entry:
                luaStr += i
            luaStr = luaStr.split('/')[-1].split('\'')[0].split('\"')[0]
            actions_lua_set.add('<%' + luaStr)

        # find the imported javascript files
        jss = re.findall(r'(?i)[\'\"][\S]*.js[\'\"]', content)
        jss_set = set()
        for jsfile in jss:
            if 'jquery' not in jsfile.lower() and 'react' not in jsfile.lower() and 'localization' not in jsfile.lower() and 'initialjs' not in jsfile.lower():
                if jsfile.endswith('.js\"') or jsfile.endswith('.js\''):
                    jsfile = jsfile.replace('\"', '').replace('\'', '')
                    jss_set.add(jsfile)

        jss_set = Utils.info_filter(jss_set, 0)
        # identify js parameters and functions in the html
        js_parameters, js_functions = self.identify_js(content, filepath)
        jsfuncs_set = Utils.info_filter(js_functions, 0)
        jsparas_set = Utils.info_filter(js_parameters, 1)

        # input variables
        names = re.findall(r'(?i)name=[\'\"](.*?)[\'\"]', content)  # <input.*?
        names_set = Utils.info_filter(set(names), 1)
        # directly defined variables by var
        vars = re.findall(r'(?i)var (.*?).*?=', content)
        vars_set = Utils.info_filter(set(vars), 1)
        # nvram IPC
        nvram_set = re.findall(r'(?i)nvram set (.*?)', content)
        nvram_get = re.findall(r'(?i)nvram get (.*?)', content)
        nvrams = nvram_set + nvram_get
        nvrams_set = Utils.info_filter(set(nvrams), 1)
        # tcWebApi IPC
        tcWebApi_set = re.findall(
            r'(?i)tcWebApi_set\(.*?,[\'\"](.*?)[\'\"],.*?\)', content)
        tcWebApi_get = re.findall(
            r'(?i)tcWebApi_get\(.*?,[\'\"](.*?)[\'\"],.*?\)', content)
        tcWebApis = tcWebApi_set + tcWebApi_get
        tcWebApis_set = Utils.info_filter(set(tcWebApis), 1)

        # find the file upload interface in the html
        uploads = re.findall(r'(?is)<input.*?type=[\'\"]file[\'\"].*?>', content)
        uploads_1 = re.findall(r'(?is)<input.*?type=file.*?>', content)
        uploads_set = set(uploads) | set(uploads_1)

        web_info['action'] = list(actions_set) + list(actions_lua_set)

        web_info['delivery'] = list(uploads_set)

        web_info['call'] = {}
        web_info['call']['js'] = list(jss_set)
        web_info['call']['html'] = []
        web_info['call']['asp'] = []
        web_info['call']['sh'] = []
        web_info['call']['elf'] = []
        web_info['call']['lua'] = []
        web_info['call']['php'] = []

        web_info['ipc'] = {}
        web_info['ipc']['action'] = list(actions_set) + list(actions_lua_set)
        web_info['ipc']['input'] = list(names_set)
        web_info['ipc']['nvram'] = list(nvrams_set)
        web_info['ipc']['tcwebapi'] = list(tcWebApis_set)
        web_info['ipc']['var'] = list(vars_set)
        web_info['ipc']['jsfunc'] = list(jsfuncs_set)
        web_info['ipc']['jspara'] = list(jsparas_set)
        
        web_info['msg'] = list(msg_list)

        if len(web_info['action']) > 0:
            web_info = self.check_files(filepath, web_info)

        return web_info

 
    def identify_js(self, content, filepath):
        parameters = set()
        functions = set()
        js = re.findall(r"(?i)<script>([\s\S]+?)</script>", content)
        js = js + re.findall(r"(?i)<script type=\"text/javascript\">([\s\S]+?)</script>", content)
        js = js + re.findall(r"(?i)<script language=\"javascript\">([\s\S]+?)</script>", content)

        for code in js:
            js_code = code.encode("utf-8")
            js_parameters, js_functions = self.js_extractor(js_code, filepath)
            parameters = parameters | js_parameters
            functions = functions | js_functions
        return parameters, functions


    def js_extractor(self, text, filepath, key=""):
        tmp_parameters = set()
        tmp_functions = set()

        content = text.decode('utf-8', 'ignore')
        # sometimes EOF exist within the js exerpt and can mess up acorn, we take that out
        content = re.sub('EOF[^EOF]+EOF', '', content)
        content = re.sub('\/<%[^%>\/]+%>\/', '', content) # remove asp code from html
        content = re.sub('<%[^%>]+%>', '', content) 
        content = re.sub('\/\*[^\/]+\*\/', '', content) # remove commented code inside html
        content = re.sub('=(\s)*;', ';', content) # some js code has ' var a = ; ', fix this

        data_dict = {"engine": "acorn", "code": content}
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post("http://localhost:3000/codeparse", headers=headers, data=json.dumps(data_dict))
            data = response.json()
            if data["code"] != 200:
                pass
            tree = data["data"]

            if key:
                keywords, functions = self.get_target_value(key, tree, [], [])
            else:
                keywords, functions = self.get_target_value("name", tree, [], [])
                keywords1, function1 = self.get_target_value("value", tree, [], [])
                keywords = list(keywords) + list(keywords1)  # Convert keywords1 to a list before concatenating
                functions = list(functions) + list(function1)

            for r in keywords:
                if isinstance(r, str):
                    tmp_parameters.add(r)
            for f in functions:
                if isinstance(f, str):
                    tmp_functions.add(f)

        except Exception as e:
            pass
        finally:
            parameters = Utils.info_filter(tmp_parameters, 1)
            functions = Utils.info_filter(tmp_functions, 0)
            return parameters, functions

    def check_files(self, filepath, web_info):
        fpaths = []

        htmls = []
        asps = []
        shs = []
        elfs = []
        luas = []
        phps = []
        jss = []

        traverse_path = os.path.join(config.FW_RESULTS, "traverse.json")
        actions = web_info["action"]

        for func in actions:
            fpath = ''
            if func.find("/") == 0:
                # cgi and html
                if func.find("?") >= 0:
                    tmp_func = func.split("?")[0]
                    if tmp_func[1:].split("/")[0] == os.path.basename(filepath[0:filepath.rfind("/")]):
                        fpath = os.path.join(filepath[0:filepath.rfind("/")], tmp_func[1:].split("/")[1])
                        fpaths.append(fpath)
                    else:
                        pattern = re.compile(r'((?:[A-Z]:|(?<![:/\\])[\\\/]|\~[\\\/]|(?:\.{1,2}[\\\/])+)[\w+\\\s_\-\(\)\/]*(?:\.\w+)*)')
                        file_names = []
                        for path in pattern.findall(tmp_func):
                            file_names.append(os.path.basename(path))
                    
                        with open(traverse_path, "r") as f:
                            files = json.load(f)
                        for name in file_names:
                            suffix = name.split(".")[-1]
                            if suffix in files:
                                for path in files[suffix]:
                                    if os.path.basename(path) == name:
                                        fpaths.append(fpath)
                            else:
                                for type in files:
                                    for path in files[type]:
                                        if os.path.basename(path) == name:
                                            fpaths.append(path)
      
                else: 
                    if os.path.isfile(func):
                        fpath = func
                        fpaths.append(fpath)
                    elif os.path.isfile(os.path.join(filepath[0:filepath.rfind("/")], func[1:])):
                        fpath = os.path.join(filepath[0:filepath.rfind("/")], func[1:])
                        fpaths.append(fpath)
                    elif func[1:].split("/")[0] == os.path.basename(filepath[0:filepath.rfind("/")]):
                        fpath = os.path.join(filepath[0:filepath.rfind("/")], func[1:].split("/")[1])
                        fpaths.append(fpath)
            elif '<%' in func:
                func = func.split('<%')[-1]
                with open(traverse_path, "r") as f:
                    files = json.load(f)
                for file in files['sh']:
                    if func == os.path.basename(file):
                        fpaths.append(file)
            else:
                if os.path.isfile(os.path.join(filepath[0:filepath.rfind("/")], func)): 
                    fpath = os.path.join(filepath[0:filepath.rfind("/")], func)
                    fpaths.append(fpath)

        for fpath in fpaths:
            filename = fpath.split('/')[-1]
            if filename == "reset":
                continue

            if fpath != '' and Utils.fetch_file(fpath, ['.html', '.htm', '.shtml']):
                htmls.append(fpath)
            
            elif fpath != '' and Utils.fetch_file(fpath, ['.asp']):
                asps.append(fpath)

            elif fpath != '' and Utils.fetch_file(fpath, ['sh']):
                shs.append(fpath)
            
            elif fpath != '' and Utils.fetch_file(fpath, ['elf']):
                elfs.append(fpath)
            
            elif fpath != '' and Utils.fetch_file(fpath, ['.lua']):
                luas.append(fpath)
            
            elif fpath != '' and Utils.fetch_file(fpath, ['.php']):
                phps.append(fpath)

            elif fpath != '' and Utils.fetch_file(fpath, ['.js']):
                jss.append(fpath)

        web_info['call']['html'] = list(set(htmls))
        web_info['call']['asp'] = list(set(asps))
        web_info['call']['sh'] = list(set(shs))
        web_info['call']['elf'] = list(set(elfs))
        web_info['call']['lua'] = list(set(luas))
        web_info['call']['php'] = list(set(phps))
        web_info['call']['js'] = web_info['call']['js'] + list(set(jss))

        return web_info


    def _get_value(self, key, val, tmp_list, func_list):
            for val_ in val:
                if isinstance(val_, dict):
                    self.get_target_value(key, val_, tmp_list, func_list)  
                elif isinstance(val_, (list, tuple)):
                    if val_:
                        self._get_value(key, val_, tmp_list, func_list)  

    def get_target_value(self, key, dic, tmp_list, func_list):
            if not isinstance(dic, dict) or not isinstance(tmp_list, list):  
                return 'argv[1] not an dict or argv[-1] not an list '

            if dic.get("type", "") == "CallExpression" and len(dic.get("arguments",[])) == 3:
                obj = dic.get("callee", None)
                if obj:
                    soapaction = obj.get("property", None)
                    if soapaction and soapaction.get("name", "") == "sendSOAPAction":
                        args = dic.get("arguments", [])
                        if args and args[0].get("type", "") == "Literal":
                            func_list.append(args[0].get("value", ""))

            if key in dic.keys() and dic.get("type", "") == "Literal":
                tmp_list.append(str(dic[key]))  
            for value in dic.values():  
                if isinstance(value, dict):
                    self.get_target_value(key, value, tmp_list, func_list)  
                elif isinstance(value, (list, tuple)):
                    if value:
                        self._get_value(key, value, tmp_list, func_list)  

            return list(set(tmp_list)), list((func_list))

    def parse(self, filepath):
        web_info = {}  # Initialize web_info variable with an empty dictionary
        if os.path.isfile(filepath): 
            if Utils.fetch_file(filepath, ['.html', '.htm', '.shtml', '.asp', '.php']):
                with open(filepath, "rb") as f:
                    text = f.read()
                web_info = self.html_asp_extractor(text, filepath)

        return web_info

    
    def search_entry(self, web_files):

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
        msg_MAX_HTML = ""
        function_MAX = 0
        function_MIN = 9999
        function_NORM_MAX = 0
        function_NORM_MIN = 9999
        function_MAX_HTML = ""
        pattern_MAX = 0
        pattern_MIN = 9999
        pattern_NORM_MAX = 0
        pattern_NORM_MIN = 9999
        pattern_MAX_HTML = ""
        
        web_dict = {}
        webinfo_path = os.path.join(config.FW_RESULTS, "webinfo.json")
        name_pattern = re.compile(
            r"^(?=.*?(firmware|fw))(?=.*?(update|upgrade|upd|upg|tool)).+$", re.I | re.M)
        
        file_list = list(self.find_update_file(web_files)) #self.web_files#
        
        for filepath in file_list:
            # analyze each web file
            web_info = self.parse(filepath)

            for html in web_info['call']['html']:
                if html not in file_list:
                    file_list.append(html)

            flag = 0
            if filepath.split("/")[-1]:
                filename = filepath.split("/")[-1]
            else:
                filename = filepath.split("/")[-2]
                
            if len(name_pattern.findall(filename)) > 0:
                flag = 1
            else:
                for item in web_info['ipc']:
                    if web_info['ipc'][item] != []:
                        flag = 1
                if not flag:
                    for item in web_info['call']:
                        if web_info['call'][item] != []:
                            flag = 1

            if flag:
                web_dict[filepath] = web_info
        
        with open(webinfo_path, 'w') as f:
            json.dump(web_dict, f)
        
        pattern1 = re.compile(
            r"^(?=.*?(firmware|fw|firm|update|upgrade|upd|upg)).+$", re.I | re.M)  #(?=.*?(update|upgrade|upd|upg))
        pattern2 = re.compile(
            r"^(?=.*?(button|upload|ver|ftp|usb|check|download))(?=.*?(firmware|fw|firm)).+$", re.I | re.M)

        for file in web_dict:
            msg_count[file] = 0
            function_count[file] = 0
            pattern_count[file] = 0
            
            msg_norm[file] = 0
            function_norm[file] = 0
            pattern_norm[file] = 0
            
            if web_dict[file]['msg'] != []:
                msg_count[file] = len(web_dict[file]['msg'])
            else:
                msg_count[file] = 0
            for item in web_dict[file]['ipc']:
                if 'action' in item:
                    continue
                else:
                    if web_dict[file]['ipc'][item] != []:
                        for innerItem in web_dict[file]['ipc'][item]:
                            if pattern1.findall(innerItem):
                                function_count[file] += 1
                            if pattern2.findall(innerItem):
                                pattern_count[file] += 1
            if web_dict[file]['delivery'] != []:
                ori_data = web_dict[file]['delivery'][0].lower()
                sub_str = '<input type="file"'
                sub_str1 = "<input type='file'"
                sub_str2 = "<input type=file"
                pattern_count[file] = ori_data.count(sub_str) + ori_data.count(sub_str1) + ori_data.count(sub_str2)
            else:
                pattern_count[file] = 0
            
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
                continue
            norm = (v - msg_MIN) / (msg_MAX - msg_MIN)
            msg_norm[k] = norm
            if count == 0:
                if norm > msg_NORM_MAX:
                    msg_NORM_MAX = norm
                elif norm < msg_NORM_MIN:
                    msg_NORM_MIN = norm
            else:
                if norm > msg_NORM_MAX:
                    msg_NORM_MAX = norm
                elif norm < msg_NORM_MIN:
                    msg_NORM_MIN = norm

        for count, (k, v) in enumerate(function_count.items()):
            if function_MAX  == function_MIN == 0:
                function_NORM_MAX = 0
                break
            elif function_MAX == function_MIN != 0:
                function_NORM_MAX = 0
                continue
            norm = (v - function_MIN) / (function_MAX - function_MIN)
            function_norm[k] = norm
            if count == 0:
                if norm > function_NORM_MAX:
                    function_NORM_MAX = norm
                elif norm < function_NORM_MIN:
                    function_NORM_MIN = norm
            else:
                if norm > function_NORM_MAX:
                    function_NORM_MAX = norm
                elif norm < function_NORM_MIN:
                    function_NORM_MIN = norm
                    
        for count, (k, v) in enumerate(pattern_count.items()):
            if pattern_MAX  == pattern_MIN == 0:
                pattern_NORM_MAX = 0
                break
            elif pattern_MAX == pattern_MIN != 0:
                pattern_NORM_MAX = 0
                continue
            norm = (v - pattern_MIN) / (pattern_MAX - pattern_MIN)
            pattern_norm[k] = norm
            if count == 0:
                if norm > pattern_NORM_MAX:
                    pattern_NORM_MAX = norm
                elif norm < pattern_NORM_MIN:
                    pattern_NORM_MIN = norm
            else:
                if norm > pattern_NORM_MAX:
                    pattern_NORM_MAX = norm
                elif norm < pattern_NORM_MIN:
                    pattern_NORM_MIN = norm
                    
        finalMax = msg_NORM_MAX
        
        if function_NORM_MAX > finalMax:
            finalMax = function_NORM_MAX

        if pattern_NORM_MAX > finalMax:
            finalMax = pattern_NORM_MAX
            
        pattern123 = {}

        for k in pattern_norm:
            for k1 in function_norm:
                if k in k1:
                    for k2 in msg_norm:
                        if k1 in k2:
                            pattern123[k] = 0.33 * msg_norm[k2] + 0.33 * function_norm[k1] + 0.33 * pattern_norm[k]
                            break
                    break

        maxPatternHTML123 = max(list(pattern123.keys()), key=lambda k: pattern123[k], default=None)
    
        return maxPatternHTML123


    # Search files containing firmware update-related patterns
    def find_update_file(self, file_list):
        search_results = []
        pattern1 = re.compile(r"^(?=.*?(firmware|fw))(?=.*?(update|upgrade|upd|upg)).+$", re.I|re.M) 
        pattern2 = re.compile(r"^(?=.*?(button|upload|ver|ftp|usb|check|download))(?=.*?(firmware|fw)).+$", re.I|re.M)

        filepaths = []
        features = []
        cluster_results = []
        
        for filepath in file_list:
            if "lang" in filepath or "help" in filepath or "login" in filepath:
                continue
            filename = filepath.split("/")[-1].split('.')[0]
            if pattern1.findall(filename) or filename=='upgrade' or filename=='update':
                search_results.append(filepath)
                continue
            if os.path.isfile(filepath):    
                with open(filepath, "rb") as f:
                    text = f.read()
                    content = text.decode('utf-8', 'ignore')

                pattern1_results = pattern1.findall(content)
                if len(pattern1_results) > 0:
                    num_pattern1 = len(pattern1_results)
                    pattern2_results = pattern2.findall(content)
                    num_pattern2 = len(pattern2_results)
                    filepaths.append(filepath)
                    features.append(num_pattern1+num_pattern2)
                    
        if len(filepaths) > 3:
            mapping = map(filepaths.__getitem__, [i for i, feature in enumerate(features) if feature >= max(features)/2])
            cluster_results = list(mapping)
        elif len(filepaths) >1 and len(filepaths) <=3:
            mapping = map(filepaths.__getitem__, [i for i, feature in enumerate(features) if feature >= max(features)/2])
            cluster_results = list(mapping)
        else:
            cluster_results = filepaths
        web_files = set(cluster_results) | set(search_results)
        
        return web_files
