import os
import re
import glob
import requests
import json
import traceback
import configs.analysis_config as config

class JSParser:
    def __init__(self):
        # patterns
        self.jspattern = re.compile(r"[\'\"][\S]*.js[\'\"]")
        self.onclickPattern = re.compile(r"on[cC]lick=[\'\"]?.*\(.*\)(;)?[\'\"]?")
        self.onloadPattern = re.compile(r"on[lL]oad=[\'\"]?.*\(.*\)(;)?[\'\"]?")
        
        # firmware update-related keywords
        self.checksumWords = ['checksum', 'md5', 'sha256', 'crc']
        self.deviceWords = ['modulename', 'device', 'model', 'module', 'platform']
        self.versionWords = ['version']
        self.signatureWords = ['signature']
        self.compareWords = ['>', '<', '>=', '<=', '==', '!=', '===']
    
    def jsFromHtml(self, file):
        rootpath = file.replace(file.split('-root/')[1], '')
        jsmatched = set()
        funcmatched = set()
        for i, line in enumerate(open(file)):
            for match in re.finditer(self.jspattern, line):
                jsbase = os.path.basename(match.group().replace('\"','').replace('\'',''))
                # look for this file globally
                for i in glob.glob(rootpath + '**/' + jsbase, recursive=True): 
                    # do not match standard js library such as react, jquery, or localization files
                    if 'jquery' not in i.lower() and 'react' not in i.lower() and 'localization' not in i.lower() and 'initialjs' not in i.lower():
                        jsmatched.add(i)
            for match in re.finditer(self.onclickPattern, line):
                funccall = (match.group().split(')')[0] + ')').split('=')[1].replace('\'','').replace('\"','').replace('return ', '')
                funcmatched.add(funccall)
            for match in re.finditer(self.onloadPattern, line):
                funccall = (match.group().split(')')[0] + ')').split('=')[1].replace('\'','').replace('\"','').replace('return ', '')
                funcmatched.add(funccall)
        # some js can nest within html, add the original html file
        jsmatched.add(file)
        self.func2js(funcmatched, jsmatched, file)
        return 

    def func2js(self, funclist, jslist, srcfile):

        dict = {}

        for func in funclist:
            tosearch = 'function ' + func.split('(')[0].strip() + '(\s)*\(' 
            for jsfile in jslist:
                with open(jsfile, 'r') as f:
                    try:
                        for line in f.readlines():
                            if re.search(tosearch, line):

                                if jsfile in dict.keys():
                                    toadd = func.split('(')[0].strip() + '()'
                                    if toadd not in dict[jsfile]:
                                        dict[jsfile].append(toadd)
                                else:
                                    dict[jsfile] = [func.split('(')[0].strip() + '()']
                    except UnicodeDecodeError:
                        pass

        ext = self.getExtCalls(dict)
        for key in ext.keys():
            for item in ext[key]:
                if item not in dict[key]:
                    dict[key].append(item)

        jsfromhtml_path = os.path.join(config.FW_RESULTS, "jsfromhtml.json")
        with open(jsfromhtml_path, 'r') as f:
            jsfromhtml_dict = json.load(f)
        if srcfile not in jsfromhtml_dict.keys():
            jsfromhtml_dict[srcfile] = {}
        
        for key in dict.keys():
            # if external js is called from the html
            if os.path.basename(key) != os.path.basename(srcfile): 
                for func in dict[key]:
                    if func not in jsfromhtml_dict[srcfile].keys():
                        funccode = self.js2ast(key, func, srcfile)
                        jsfromhtml_dict[srcfile][func] = {'code': funccode, 'srcpath': key, 'type': 'external'}
                
            # if js is documented within the html
            else:
                for func in dict[key]:
                    if func not in jsfromhtml_dict[srcfile].keys():
                        funccode = self.js2ast(key, func, srcfile)
                        jsfromhtml_dict[srcfile][func] = {'code': funccode, 'srcpath': key, 'type': 'internal'}
        
        with open(jsfromhtml_path, 'w') as f:
            json.dump(jsfromhtml_dict, f)
                    
    def getExtCalls(self, dict):
        extCalls = {}
        # get func called directly by func in file, add them to dict too
        for key in dict.keys():
            extCalls[key] = []
            allfunc = self.getAllFunc(key)
            with open(key, "rb") as f:
                text = f.read()
            content = text.decode('utf-8', 'ignore')

            for funcname in dict[key]:
                funcpattern = "function " + funcname.split('(')[0].strip() + "(\s)*\(([\s\S]+?)(?=function (\S)+\()" # matches until the next func
                funcpattern2 = "function " + funcname.split('(')[0].strip() + "(\s)*\(([\s\S]+?)(?=script)" # matches until the end of script
                funccode = re.findall(funcpattern, content)#[0]
                if not funccode:
                    funccode = re.findall(funcpattern2, content)#[0]
                if funccode:
                    funccode = funccode[0]
                    if type(funccode) == tuple:
                        funccode = ''.join(funccode)

                    funccode = re.sub('EOF[^EOF]+EOF', '', funccode) # remove shell code inside html
                    funccode = re.sub('\/<%[^%>/]+%>\/', '', funccode) # remove asp code from html
                    funccode = re.sub('<%[^%>]+%>', '', funccode) 
                    funccode = "function " + funcname.split('(')[0] + '(' + funccode

                    if not funccode.rstrip().endswith('}'):
                        tail = funccode.split('}')[-1]
                        funccode = funccode.replace(tail, '')
                    
                    for extfunc in allfunc:
                        if extfunc.replace(')', '') in funccode and extfunc != funcname and not extfunc in dict[key]:
                            if extfunc not in extCalls[key]:
                                extCalls[key].append(extfunc)
        return extCalls
    

    def js2ast(self, filepath, funcname, callpath):
        # filepath: filepath where the function is defined
        # funcname: function name
        # callpath: html file path calling the function
        funccode = ''
        try:
            with open(filepath, "rb") as f:
                text = f.read()
            content = text.decode('utf-8', 'ignore')
            funcpattern = "function " + funcname.split('(')[0].strip() + "(\s)*\(([\s\S]+?)(?=function (\S)+\()" # matches until the next func
            funcpattern2 = "function " + funcname.split('(')[0].strip() + "(\s)*\(([\s\S]+?)(?=script)" # matches until the end of script

            funccode = re.findall(funcpattern, content)
            if not funccode:
                funccode = re.findall(funcpattern2, content)#[0]
            if not funccode:
                return
            funccode = funccode[0]
            if type(funccode) == tuple:
                funccode = ''.join(funccode)

            funccode = re.sub('EOF[^EOF]+EOF', '', funccode) # remove shell code inside html
            funccode = re.sub('\/<%[^%>\/]+%>\/', '', funccode) # remove asp code from html
            funccode = re.sub('<%[^%>]+%>', '', funccode) 
            funccode = re.sub('\/\*[^\/]+\*\/', '', funccode) # remove commented code inside html
            funccode = re.sub('=(\s)*;', ';', funccode) # some js code has ' var a = ; ', fix this

            funccode = "function " + funcname.split('(')[0] + '(' + funccode

            if not funccode.rstrip().endswith('}'):
                tail = funccode.split('}')[-1]
                funccode = funccode.replace(tail, '')
            
            data_dict = {"engine": "acorn", "code": funccode}
            headers = {'Content-Type': 'application/json'}                                                      
            response = requests.post("http://localhost:3000/codeparse", headers=headers, data=json.dumps(data_dict))
            data = response.json()


            if 'code' in data:
                if data['code'] != 200:
                    print("Error code 500")
                    pass
            if 'data' in data:
                tree = data["data"]
                self.js_analyze(tree, funccode, funcname, filepath, callpath)
        except Exception as e:
            print(traceback.format_exc())
            pass
        
        finally:
            return funccode
        
    def getAllFunc(self, filepath):
        allfunc = []
        with open(filepath, "rb") as f:
            text = f.read()
        content = text.decode('utf-8', 'ignore')
        anyfuncpattern = "function.*\S.*\("
        for item in re.findall(anyfuncpattern, content):
            item = item.replace('function ', '') + ')'
            if len(item) > 7:
                allfunc.append(item)
        return allfunc
    
    def js_analyze(self, tree, src, funcname, filepath, callpath):
        global js_path
        js_path = os.path.join(config.FW_RESULTS, "js.json")
        if self.checkfuncname(funcname, filepath, src, callpath):
            return
        else:
            self.jsonBFS(tree, src, funcname, filepath, callpath, [])
    
    def checkfuncname(self, name, path, code, callpath):
        code = code.replace('\n', ' ').replace('\r', '')
        for keywords in self.versionWords:
            if keywords in name.lower():
                if not os.path.isfile(js_path):
                    with open(js_path, 'w') as f:
                        json.dump({}, f)
                try:
                    with open(js_path, 'r') as f:
                        web_content = f.read()
                        js_dict = json.loads(r''.format(web_content))
                except:
                    js_dict = {}
                if not js_dict or js_dict == {}:
                    js_dict = {}
                if not callpath in js_dict.keys():
                    js_dict[callpath] = {}
                if not name in js_dict[callpath].keys():
                    js_dict[callpath][name] = {}
                    js_dict[callpath][name]["version"] = [code]
                    js_dict[callpath][name]["sourcepath"] = path
                with open(js_path, 'w') as f:
                    json.dump(js_dict, f)
                return True
        for keywords in self.deviceWords:
            if keywords in name.lower():
                if not os.path.isfile(js_path):
                    with open(js_path, 'w') as f:
                        json.dump({}, f)
                try:
                    with open(js_path, 'r') as f:
                        web_content = f.read()
                        js_dict = json.loads(r''.format(web_content))
                except:
                    js_dict = {}
                if not js_dict or js_dict == {}:
                    js_dict = {}
                if not callpath in js_dict.keys():
                    js_dict[callpath] = {}
                if not name in js_dict[callpath].keys():
                    js_dict[callpath][name] = {}
                    js_dict[callpath][name]["device"] = [code]
                    js_dict[callpath][name]["sourcepath"] = path
                with open(js_path, 'w') as f:
                    json.dump(js_dict, f)
                return True
        for keywords in self.checksumWords:
            if keywords in name.lower():
                if not os.path.isfile(js_path):
                    with open(js_path, 'w') as f:
                        json.dump({}, f)
                try:
                    with open(js_path, 'r') as f:
                        web_content = f.read()
                        js_dict = json.loads(r''.format(web_content))
                except:
                    js_dict = {}
                if not js_dict or js_dict == {}:
                    js_dict = {}
                if not callpath in js_dict.keys():
                    js_dict[callpath] = {}
                if not name in js_dict[callpath].keys():
                    js_dict[callpath][name] = {}
                    js_dict[callpath][name]["checksum"] = [code]
                    js_dict[callpath][name]["sourcepath"] = path
                with open(js_path, 'w') as f:
                    json.dump(js_dict, f)
                return True
        for keywords in self.signatureWords:
            if keywords in name.lower():
                if not os.path.isfile(js_path):
                    with open(js_path, 'w') as f:
                        json.dump({}, f)
                try:
                    with open(js_path, 'r') as f:
                        web_content = f.read()
                        js_dict = json.loads(r''.format(web_content))
                except:
                    js_dict = {}
                if not js_dict or js_dict == {}:
                    js_dict = {}
                if not callpath in js_dict.keys():
                    js_dict[callpath] = {}
                if not name in js_dict[callpath].keys():
                    js_dict[callpath][name] = {}
                    js_dict[callpath][name]["signature"] = [code]
                    js_dict[callpath][name]["sourcepath"] = path
                with open(js_path, 'w') as f:
                    json.dump(js_dict, f)
                return True
        return False
    
    def jsonBFS(self, tree, src, funcname, srcpath, callpath, idslist):
        for node in tree:
            self.process(tree, node, src, funcname, srcpath, callpath, idslist)
            if type(tree[node]) == list: # sometimes acorn outputs a list, instead of a json under a key
                for subtree in tree[node]:
                    self.jsonBFS(subtree, src, funcname, srcpath, callpath, idslist)
            elif type(tree[node]) == dict: 
                self.jsonBFS(tree[node], src, funcname, srcpath, callpath, idslist)


    def process(self, tree, node, src, funcname, srcpath, callpath, idslist):
        # discard if node is not "type" and value is not "IFStatement"
        if node != "type" or tree[node] != "IfStatement": 
            return
        # look for its immediate neighbor "test", and infer "type"
        # BinaryExpression: if (a.b.c ops d.e.f) then ... 
        if tree["test"]["type"] != "BinaryExpression":
            return
        # check if operator is what we want
        if tree["test"]["operator"] not in self.compareWords:
            return
        # left and right are both subtree (rich python dict), gather variables from those
        lhs = tree["test"]["left"]
        rhs = tree["test"]["right"]
        # gather identifiers
        ids = self.getIdentifiers(lhs, set()) | self.getIdentifiers(rhs, set())
        # some lines have ids identical from other lines, identify those
        if ids in idslist:
            return
        else:
            idslist.append(ids)
        treeinfo = [funcname, str(tree["start"]), str(tree["end"]), srcpath, callpath]
        self.getAliases(ids, src, 0, [], [], treeinfo)

    def getIdentifiers(self, subtree, identifiers = set()):
        for node in subtree:
            if node == "name":
                identifiers.add(subtree["name"])
            if type(subtree[node]) == list:
                for littletree in subtree[node]:
                    self.getIdentifiers(littletree, identifiers)
            elif type(subtree[node]) == dict:
                self.getIdentifiers(subtree[node], identifiers)
        return identifiers

    def getAliases(self, variables, sourcecode, count, varlist, linelist, info):
        if count > 10:
            return
        for variable in variables:
            if variable in varlist or len(variable) < 4:
                continue
            else:
                varlist.append(variable)
            # the exit condition is if variable contains version
            sourcecodeline = sourcecode.replace('\n', ' ').replace('\r', ' ')
            for keywords in self.versionWords:
                if keywords in variable.lower():
                    if not os.path.isfile(js_path):
                        with open(js_path, 'w') as f:
                            json.dump({}, f)
                    try:
                        with open(js_path, 'r') as f:
                            web_content = f.read()
                            js_dict = json.loads(r''.format(web_content))
                    except:
                        js_dict = {}
                    if not js_dict or js_dict == {}:
                        js_dict = {}
                    if not info[4] in js_dict.keys():
                        js_dict[info[4]] = {}
                    if not info[0] in js_dict[info[4]]:
                        js_dict[info[4]][info[0]] = {}
                        if 'version' not in js_dict[info[4]][info[0]]:
                            js_dict[info[4]][info[0]]["version"] = []
                        js_dict[info[4]][info[0]]["version"].append(sourcecodeline[int(info[1]):int(info[2])])
                        js_dict[info[4]][info[0]]["sourcecode"] = sourcecodeline
                        js_dict[info[4]][info[0]]["sourcepath"] = info[3]
                    else:
                        if 'version' not in js_dict[info[4]][info[0]]:
                            js_dict[info[4]][info[0]]["version"] = []
                        if sourcecodeline[int(info[1]):int(info[2])] not in js_dict[info[4]][info[0]]["version"]:
                            js_dict[info[4]][info[0]]["version"].append(sourcecodeline[int(info[1]):int(info[2])])
                    with open(js_path, 'w') as f:
                        json.dump(js_dict, f)
                    return True
            for keywords in self.deviceWords:
                if keywords in variable.lower():
                    if not os.path.isfile(js_path):
                        with open(js_path, 'w') as f:
                            json.dump({}, f)
                    try:
                        with open(js_path, 'r') as f:
                            web_content = f.read()
                            js_dict = json.loads(r''.format(web_content))
                    except:
                        js_dict = {}
                    if not js_dict or js_dict == {}:
                        js_dict = {}
                    if not info[4] in js_dict.keys():
                        js_dict[info[4]] = {}
                    if not info[0] in js_dict[info[4]].keys():
                        js_dict[info[4]][info[0]] = {}
                        if 'device' not in js_dict[info[4]][info[0]].keys():
                            js_dict[info[4]][info[0]]["device"] = []
                        js_dict[info[4]][info[0]]["device"].append(sourcecodeline[int(info[1]):int(info[2])])
                        js_dict[info[4]][info[0]]["sourcecode"] = sourcecodeline
                        js_dict[info[4]][info[0]]["sourcepath"] = info[3]
                    else:
                        if 'device' not in js_dict[info[4]][info[0]]:
                            js_dict[info[4]][info[0]]["device"] = []
                        if sourcecodeline[int(info[1]):int(info[2])] not in js_dict[info[4]][info[0]]["device"]:
                            js_dict[info[4]][info[0]]["device"].append(sourcecodeline[int(info[1]):int(info[2])])
                    with open(js_path, 'w') as f:
                        json.dump(js_dict, f)
                    return True
            for keywords in self.checksumWords:
                if keywords in variable.lower():
                    if not os.path.isfile(js_path):
                        with open(js_path, 'w') as f:
                            json.dump({}, f)
                    try:
                        with open(js_path, 'r') as f:
                            web_content = f.read()
                            js_dict = json.loads(r''.format(web_content))
                    except:
                        js_dict = {}
                    if not js_dict or js_dict == {}:
                        js_dict = {}
                    if not info[4] in js_dict.keys():
                        js_dict[info[4]] = {}
                    if not info[0] in js_dict[info[4]].keys():
                        js_dict[info[4]][info[0]] = {}
                        if 'checksum' not in js_dict[info[4]][info[0]].keys():
                            js_dict[info[4]][info[0]]["checksum"] = []
                        js_dict[info[4]][info[0]]["checksum"].append(sourcecodeline[int(info[1]):int(info[2])])
                        js_dict[info[4]][info[0]]["sourcecode"] = sourcecodeline
                        js_dict[info[4]][info[0]]["sourcepath"] = info[3]
                    else:
                        if 'checksum' not in js_dict[info[4]][info[0]]:
                            js_dict[info[4]][info[0]]["checksum"] = []
                        if sourcecodeline[int(info[1]):int(info[2])] not in js_dict[info[4]][info[0]]["checksum"]:
                            js_dict[info[4]][info[0]]["checksum"].append(sourcecodeline[int(info[1]):int(info[2])])
                    with open(js_path, 'w') as f:
                        json.dump(js_dict, f)
                    return True
            for keywords in self.signatureWords:
                if keywords in variable.lower():
                    if not os.path.isfile(js_path):
                        with open(js_path, 'w') as f:
                            json.dump({}, f)
                    try:
                        with open(js_path, 'r') as f:
                            web_content = f.read()
                            js_dict = json.loads(r''.format(web_content))
                    except:
                        js_dict = {}
                    if not js_dict or js_dict == {}:
                        js_dict = {}
                    if not info[4] in js_dict.keys():
                        js_dict[info[4]] = {}
                    if not info[0] in js_dict[info[4]].keys():
                        js_dict[info[4]][info[0]] = {}
                        if 'signature' not in js_dict[info[4]][info[0]].keys():
                            js_dict[info[4]][info[0]]["signature"] = []
                        js_dict[info[4]][info[0]]["signature"].append(sourcecodeline[int(info[1]):int(info[2])])
                        js_dict[info[4]][info[0]]["sourcecode"] = sourcecodeline
                        js_dict[info[4]][info[0]]["sourcepath"] = info[3]
                    else:
                        if 'signature' not in js_dict[info[4]][info[0]]:
                            js_dict[info[4]][info[0]]["signature"] = []
                        if sourcecodeline[int(info[1]):int(info[2])] not in js_dict[info[4]][info[0]]["signature"]:
                            js_dict[info[4]][info[0]]["signature"].append(sourcecodeline[int(info[1]):int(info[2])])
                    with open(js_path, 'w') as f:
                        json.dump(js_dict, f)
                    return True
            relatedlines = set()
            # check patter for "variable =" or "variable="
            setterpattern = variable + '.*='
            slicedsourcecode = sourcecode.split('\n')
            for line in slicedsourcecode:
                # a proper setter function should end with ';'
                if re.search(setterpattern, line) and line.strip().endswith(';'):
                        relatedlines.add(line.strip())
            for line in relatedlines:
                if line in linelist:
                    continue
                else:
                    linelist.append(line)
                if 'return' in line: # this should only be a line with identifiers, inline function overriden with return will cause error in acorn
                    line = line.split('return')[0] + ';'
                data_dict = {"engine": "acorn", "code": line}
                headers = {'Content-Type': 'application/json'}
                try:
                    response = requests.post("http://localhost:3000/codeparse", headers=headers, data=json.dumps(data_dict))
                    data = response.json()

                    if 'code' in data:
                        if data['code'] != 200:
                            print("Error code 500")
                            pass
                    if 'data' in data:
                        tree = data["data"]
                        ids = self.getIdentifiers(tree, set())
                        count += 1
                        if self.getAliases(ids, sourcecode, count, varlist, linelist, info):
                            return True
                
                except Exception as e:
                    print(traceback.format_exc())
                    pass
