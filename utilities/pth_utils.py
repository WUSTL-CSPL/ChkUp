import os
import stat
import re
import magic
import glob 
import json

class Utils:
    """
    class for getting all the files in the file system
    """
    # Fetch files with the specific suffix
    @staticmethod
    def fetch_file(filepath, suffix_list):
        if not os.path.exists(filepath):
            return False
        if suffix_list == ['elf']:
            try:
                states = os.stat(filepath)
                mode = states[stat.ST_MODE]
                if not stat.S_ISREG(mode) or stat.S_ISLNK(mode): 
                    return False
                try:
                    with open(filepath, 'rb') as f:
                        header = (bytearray(f.read(4))[1:4]).decode(encoding="utf-8")
                        if header in ["ELF"]:
                            return True
                except:
                    pass
            except UnicodeDecodeError as e:
                pass
        elif suffix_list == ['sh']: 
            try:
                if filepath.lower().endswith('.sh'):
                    states = os.stat(filepath)
                    mode = states[stat.ST_MODE]
                    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode): 
                        return False
                    try:
                        with open(filepath, 'rb') as f:
                            header = (bytearray(f.read(4))[1:4]).decode(encoding="utf-8")
                            if header in ["ELF"]:
                                return False
                    except:
                        pass
                    return True
                else:
                    states = os.stat(filepath)
                    mode = states[stat.ST_MODE]
                    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode): 
                        return False
                    try:
                        with open(filepath, 'rb') as f:
                            header = (bytearray(f.read(9))[0:9]).decode(encoding="utf-8")
                            if header in ["#!/bin/sh"]:
                                return True
                    except:
                        pass
            except UnicodeDecodeError as e:
                pass
        elif suffix_list == ['bc']:
            try:
                magic_result = magic.from_file(filepath)
                if "bytecode" in magic_result:
                    return True
                else:
                    return False
            except:
                pass
        else:
            suffixes = tuple(suffix_list)
            if filepath.lower().endswith(suffixes):
                return True
	

    # Traverse the whole file system to list all the files
    @staticmethod
    def traverse_file(filepath, traverse_path):
        files = {}

        html_files = []
        js_files = []
        xml_files = []
        asp_files = []

        sh_files = []
        lua_files = []
        php_files = []

        elf_files = []
        bytecode_files = []
        other_files = []

        for (root, dirs, filenames) in os.walk(filepath):
            for file in filenames:
                filepath = os.path.join(root, file)
                if os.path.isfile(filepath):
                    # Find HTML files
                    if Utils.fetch_file(filepath, [".html", ".htm", ".shtml"]):
                        html_files.append(filepath)
                    # Find JS files
                    elif Utils.fetch_file(filepath, [".js"]):
                        js_files.append(filepath)
                    # Find XML files
                    elif Utils.fetch_file(filepath, [".xml"]):
                        xml_files.append(filepath)
                    # Find ASP files
                    elif Utils.fetch_file(filepath, [".asp"]):
                        asp_files.append(filepath)
                    # Find PHP files
                    elif Utils.fetch_file(filepath, [".php"]):
                        php_files.append(filepath)
                    # Find SH files
                    elif Utils.fetch_file(filepath, ["sh"]):
                        sh_files.append(filepath)
                    # Find ELF files
                    elif Utils.fetch_file(filepath, ["elf"]):
                        elf_files.append(filepath)
                    # Find LUA bytecode
                    elif Utils.fetch_file(filepath, ['bytecode']):
                        bytecode_files.append(filepath)
                    # Find LUA source code
                    elif Utils.fetch_file(filepath, [".lua"]):
                        lua_files.append(filepath)
                    else:
                        other_files.append(filepath)
                    
        files['html'] = html_files
        files['js'] = js_files
        files['xml'] = xml_files
        files['asp'] = asp_files

        files['sh'] = sh_files
        files['lua'] = lua_files
        files['php'] = php_files

        
        files['elf'] = elf_files
        files['bytecode'] = bytecode_files
        files['others'] = other_files

        with open(traverse_path, 'w') as f:
            json.dump(files, f)

        return files


    @staticmethod
    def info_filter(keywords, flag):
        pattern = re.compile(r'[^a-zA-Z0-9\_\.\/]')
        FILTER_STRINGS = {"", " ","!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "+", "{", "}", "[", "]", \
        ":", ";", "'", '\"', ",", ".", "?", "/", ",", "<", ">", "\\", "|", "，", "？", "!", "=", "false", "true", \
        "progress", "enable", "disabled", "action"}
        keywords_remove = []
        
        if flag == 1:
            for keyword in keywords:
                if len(keyword) <= 4 or keyword.isnumeric() or len(pattern.findall(keyword))>0:
                    keywords_remove.append(keyword)
                
                elif keyword.startswith("_"):
                    keywords_remove.append(keyword)
                elif len(keyword) >= 25:
                    keywords_remove.append(keyword)
                elif keyword.startswith("<#") and keyword.endswith("#>"):
                    keywords_remove.append(keyword)
                elif keyword.lower() in FILTER_STRINGS:
                    keywords_remove.append(keyword)
        
        elif flag == 0:
            for keyword in keywords:
                if len(keyword) <=4 or keyword.isnumeric(): #or len(pattern.findall(function))>0
                    keywords_remove.append(keyword)
                elif keyword.lower() in FILTER_STRINGS:
                    keywords_remove.append(keyword)
        
        keywords = keywords - set(keywords_remove)
        return keywords
    

    @staticmethod
    def solve_symlink(filepath):
        if os.path.islink(filepath):
            filepath = os.readlink(filepath)
        return filepath


    @staticmethod
    def getRoot(path):
        if path.endswith('-root'):
            return path
        files = list(filter(lambda f: os.path.isdir(f), glob.glob(path + '*'))) + \
            list(filter(lambda f: os.path.isdir(f), glob.glob(path + '*/*'))) + \
                list(filter(lambda f: os.path.isdir(f), glob.glob(path + '*/*/*'))) + \
                    list(filter(lambda f: os.path.isdir(f), glob.glob(path + '*/*/*/*')))
        
        fs_dirs = []
        for file in files:
            if file.endswith('-root'):
            # if '-root' in os.path.basename(file):
                fs_dirs.append(file)
        return fs_dirs
