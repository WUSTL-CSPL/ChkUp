import os
import json
import random
import traceback
from collections import OrderedDict
import configs.analysis_config as config
from exec_pth_rec.program_node import Node
from utilities.pth_utils import Utils
from exec_pth_rec.shell_syntax_parser import usualCommands, shell_results
from exec_pth_rec.control_flows.bin_cfg import BinCFGGenerator
from exec_pth_rec.control_flows.js_cfg import JSCFGGenerator
from exec_pth_rec.control_flows.shell_cfg import ShellCFGGenerator
import networkx as nx
import pickle
import time



class UFGConstructor:
    """
    recovery the UFG
    input: update entry program and update entry program type; output: UFG
    """
    def __init__(self, web_parser, js_parser, shell_parser, binary_parser):
        self.entry_path = None 
        self.entry_type = None 
        self.web_parser = web_parser
        self.js_parser = js_parser
        self.shell_parser = shell_parser
        self.binary_parser = binary_parser
        self.bin_cfg_generator = BinCFGGenerator()
        self.js_cfg_generator = JSCFGGenerator()
        self.shell_cfg_generator = ShellCFGGenerator()
        
    
    def ufg_construct(self, entry_path, entry_type):
        self.entry_path = entry_path
        self.entry_type = entry_type
         
        # Initialize results_dict
        if not os.path.exists(self.entry_path):
            return
        results_path = os.path.join(config.FW_RESULTS, "results.json")
        results_dict = dict()
        results_dict[self.entry_type] = dict()
        results_dict[self.entry_type][self.entry_path] = dict()
        with open(results_path, 'w') as f:
            json.dump(results_dict, f)
        
        # Set the entry node
        entry_node = Node(None, self.entry_path, self.entry_type, None)
        
        # Explore firmware update-related programs from the entry node
        self.program_explore(entry_node)
        
        # Build the UFGs
        results_path = os.path.join(config.FW_RESULTS, "results.json")
        with open(results_path, 'r') as f:
            results_dict = json.load(f)
        path_dict = OrderedDict(results_dict[self.entry_type])
        ufgs = []
        for key in path_dict:
            cfgs = []
            for program in path_dict[key]:
                filename = program.split("/")[-1]
                program_type = path_dict[key][program]["filetype"]
                
                ipc_keywords = []
                if path_dict[key][program]["keywords"]:
                    for item in path_dict[key][program]["keywords"]["para"]:
                        ipc_keywords.append(item)
                    for item in path_dict[key][program]["keywords"]["func"]:
                        ipc_keywords.append(item)
                
                cfg = None
                proj = None
                # first, build a cfg for each program
                graph_path = os.path.join(config.UFG_RESULTS, filename+".pkl")
                if os.path.exists(graph_path):
                    with open(graph_path, 'rb') as f:
                        cfg = pickle.load(f)
                else:
                    if program_type == 'html':
                        jsfromhtml_path = os.path.join(config.FW_RESULTS, "jsfromhtml.json")
                        with open(jsfromhtml_path, 'r') as f:
                            jsfromhtml_dict = json.load(f)
                        if program in jsfromhtml_dict:
                            if jsfromhtml_dict[program] != {}:
                                cfg, duration = self.js_cfg_generator.generate_cfg_jsfromhtml(jsfromhtml_dict[program])
                        # use ghidra to find the address of the string
                        # then use angr to get the functions that refer the string
                        # connect the cfgs
                    elif program_type == 'elf':
                        proj, cfg, duration = self.bin_cfg_generator.generate_cfg(program)

                    elif program_type == 'sh':
                        cfg, duration = self.shell_cfg_generator.generate_cfg(program)
                
                    with open(graph_path, 'wb') as f:
                        pickle.dump(cfg, f)
                
                # second, analyze the IPC/invocation relationship between programs  
                # namely, if the cfg is built scuccessfully, try to connect the cfgs
                # the key is to find the nodes in each cfg for connection
                # for each cfg, we try to connect it to the previous cfg
                # If previous cfg is None, we create a node to represent the program
                # If the cfg is not built successfully, we create a node to represent the program
                
                # the tuple represents (program, program_type, cfg, list of called nodes, list of calling nodes)
                if not cfg:
                    cfg = nx.MultiDiGraph()
                    cfg.add_node(program)
                    
                if program_type == "elf":
                    curr_num_nodes = cfg.graph.number_of_nodes()
                else:
                    curr_num_nodes = cfg.number_of_nodes()
                
                if path_dict[key][program]["callway"] == "":
                    cfgs.append((program, program_type, cfg, [], []))

                elif path_dict[key][program]["callway"] == "invocation":   
                    prev_cfg = cfgs[-1]
                    prev_graph = prev_cfg[2]
                    prev_program_type = prev_cfg[1]
                    
                    if prev_program_type == "elf":
                        prev_num_nodes = prev_graph.graph.number_of_nodes()
                    else:
                        prev_num_nodes = prev_graph.number_of_nodes()
                    
                    # get the node in the previous cfg for connect the current cfg
                    prev_conn_nodes = []
                    # get the entry node for connection as the number of nodes is 1 
                    if prev_num_nodes == 1:
                        if prev_program_type == "html":
                            prev_conn_nodes = [self.js_cfg_generator.get_entry_node(prev_graph)]
                        elif prev_program_type == "sh":
                            prev_conn_nodes = [self.shell_cfg_generator.get_entry_node(prev_graph)]
                        elif prev_program_type == "elf":
                            if proj:
                                prev_conn_nodes = [self.bin_cfg_generator.get_entry_node_proj(proj, prev_graph)]
                            else:
                                prev_conn_nodes = [self.bin_cfg_generator.get_entry_node(prev_graph.graph)]
                    
                    # try to find the nodes in the previous cfg for connection
                    else:
                        if prev_program_type == "html":
                            prev_conn_nodes = self.js_cfg_generator.get_node_by_str(prev_graph, filename)
                        elif prev_program_type == "sh":
                            prev_conn_nodes = self.shell_cfg_generator.get_node_by_str(prev_graph, filename)
                        elif prev_program_type == "elf":
                            prev_conn_nodes = self.bin_cfg_generator.get_node_invocation(program, prev_graph, filename)
                    
                    # if the conn_node_label is not found, we try to get the exit node for connection   
                    if prev_conn_nodes == []:
                        if prev_program_type == "html":
                            prev_conn_nodes = [self.js_cfg_generator.get_exit_node(prev_graph)]
                        elif prev_program_type == "sh":
                            prev_conn_nodes = [self.shell_cfg_generator.get_exit_node(prev_graph)]
                        elif prev_program_type == "elf":
                            prev_conn_nodes = [self.bin_cfg_generator.get_exit_node(prev_graph)]
                    
                    # get the node in the current cfg for being connected by the previous cfg
                    curr_conn_nodes = []
                    if prev_program_type == "html":
                        curr_conn_nodes = [self.js_cfg_generator.get_entry_node(cfg)]
                    elif prev_program_type == "sh":
                        curr_conn_nodes = [self.shell_cfg_generator.get_entry_node(cfg)]
                    elif prev_program_type == "elf":
                        curr_conn_nodes = [self.bin_cfg_generator.get_entry_node(cfg.graph)]
                        
                    # update the information of the previous cfg and append the current cfg to the cfgs
                    cfgs[-1] = (prev_cfg[0], prev_cfg[1], prev_cfg[2], prev_cfg[3], prev_conn_nodes)
                    cfgs.append((program, program_type, cfg, curr_conn_nodes, []))             
                
                elif path_dict[key][program]["callway"] == "IPC":
                    prev_cfg = cfgs[-1]
                    prev_graph = prev_cfg[2]
                    prev_num_nodes = prev_graph.number_of_nodes()
                    prev_program_type = prev_cfg[1]
                    
                    # get the node in the previous cfg for connect the current cfg
                    prev_conn_nodes = []
                    # get the entry node for connection as the number of nodes is 1 
                    if prev_num_nodes == 1:
                        if prev_program_type == "html":
                            prev_conn_nodes = [self.js_cfg_generator.get_entry_node(prev_graph)]
                        elif prev_program_type == "sh":
                            prev_conn_nodes = [self.shell_cfg_generator.get_entry_node(prev_graph)]
                        elif prev_program_type == "elf":
                            if proj:
                                prev_conn_nodes = [self.bin_cfg_generator.get_entry_node_proj(proj, prev_graph)]
                            else:
                                prev_conn_nodes = [self.bin_cfg_generator.get_entry_node(prev_graph.graph)]

                    # try to find the nodes in the previous cfg for connection
                    else:
                        if prev_program_type == "html":
                            for keyword in ipc_keywords:
                                prev_conn_nodes = prev_conn_nodes + self.js_cfg_generator.get_node_by_str(prev_graph, keyword)
                        elif prev_program_type == "sh":
                            for keyword in ipc_keywords:
                                prev_conn_nodes = prev_conn_nodes + self.shell_cfg_generator.get_node_by_str(prev_graph, keyword)
                        elif prev_program_type == "elf":
                            for keyword in ipc_keywords:
                                prev_conn_nodes = prev_conn_nodes + self.bin_cfg_generator.get_node_ipc(program, prev_graph, keyword)
                    
                    # if the conn_node_label is not found, we try to get the exit node for connection   
                    if prev_conn_nodes == []:
                        if prev_program_type == "html":
                            prev_conn_nodes = [self.js_cfg_generator.get_exit_node(prev_graph)]
                        elif prev_program_type == "sh":
                            prev_conn_nodes = [self.shell_cfg_generator.get_exit_node(prev_graph)]
                        elif prev_program_type == "elf":
                            prev_conn_nodes = [self.bin_cfg_generator.get_exit_node(prev_graph)]

                    # get the node in the current cfg for being connected by the previous cfg
                    curr_conn_nodes = []
                    
                    # get the entry node for connection as the number of nodes is 1 
                    if curr_num_nodes == 1:
                        if program_type == "html":
                            curr_conn_nodes = [self.js_cfg_generator.get_entry_node(cfg)]
                        elif program_type == "sh":
                            curr_conn_nodes = [self.shell_cfg_generator.get_entry_node(cfg)]
                        elif program_type == "elf":
                            if proj:
                                curr_conn_nodes = [self.bin_cfg_generator.get_entry_node_proj(proj, cfg)]
                            else:
                                curr_conn_nodes = [self.bin_cfg_generator.get_entry_node(cfg.graph)]

                    # try to find the nodes in the previous cfg for connection
                    else:
                        if program_type == "html":
                            for keyword in ipc_keywords:
                                curr_conn_nodes = curr_conn_nodes + self.js_cfg_generator.get_node_by_str(cfg, keyword)
                        elif program_type == "sh":
                            for keyword in ipc_keywords:
                                curr_conn_nodes = curr_conn_nodes + self.shell_cfg_generator.get_node_by_str(cfg, keyword)
                        elif program_type == "elf":
                            for keyword in ipc_keywords:
                                curr_conn_nodes = curr_conn_nodes + self.bin_cfg_generator.get_node_ipc(program, cfg, keyword)
                    
                    # if the conn_node_label is not found, we try to get the exit node for connection   
                    if curr_conn_nodes == []:
                        if program_type == "html":
                            curr_conn_nodes = [self.js_cfg_generator.get_exit_node(cfg)]
                        elif program_type == "sh":
                            curr_conn_nodes = [self.shell_cfg_generator.get_exit_node(cfg)]
                        elif program_type == "elf":
                            curr_conn_nodes = [self.bin_cfg_generator.get_exit_node(cfg)]
                            
                    # update the information of the previous cfg and append the current cfg to the cfgs
                    cfgs[-1] = (prev_cfg[0], prev_cfg[1], prev_cfg[2], prev_cfg[3], prev_conn_nodes)
                    cfgs.append((program, program_type, cfg, curr_conn_nodes, []))                        
                    
                elif path_dict[key][program]["callway"] == "invocation":   
                    prev_cfg = cfgs[-1]
                    prev_graph = prev_cfg[2]
                    prev_num_nodes = prev_graph.number_of_nodes()
                    prev_program_type = prev_cfg[1]
                    
                    # get the node in the previous cfg for connect the current cfg
                    prev_conn_nodes = []
                    # get the entry node for connection as the number of nodes is 1 
                    if prev_num_nodes == 1:
                        if prev_program_type == "html":
                            prev_conn_nodes = [self.js_cfg_generator.get_entry_node(prev_graph)]
                        elif prev_program_type == "sh":
                            prev_conn_nodes = [self.shell_cfg_generator.get_entry_node(prev_graph)]
                        elif prev_program_type == "elf":
                            if proj:
                                prev_conn_nodes = [self.bin_cfg_generator.get_entry_node_proj(proj, prev_graph)]
                            else:
                                prev_conn_nodes = [self.bin_cfg_generator.get_entry_node(prev_graph.graph)]
                    
                    # try to find the nodes in the previous cfg for connection
                    else:
                        if prev_program_type == "html":
                            prev_conn_nodes = self.js_cfg_generator.get_node_by_str(prev_graph, filename)
                        elif prev_program_type == "sh":
                            prev_conn_nodes = self.shell_cfg_generator.get_node_by_str(prev_graph, filename)
                        elif prev_program_type == "elf":
                            prev_conn_nodes = self.bin_cfg_generator.get_node_invocation(program, prev_graph, filename)
                    
                    # if the conn_node_label is not found, we try to get the exit node for connection   
                    if prev_conn_nodes == []:
                        if prev_program_type == "html":
                            prev_conn_nodes = [self.js_cfg_generator.get_exit_node(prev_graph)]
                        elif prev_program_type == "sh":
                            prev_conn_nodes = [self.shell_cfg_generator.get_exit_node(prev_graph)]
                        elif prev_program_type == "elf":
                            prev_conn_nodes = [self.bin_cfg_generator.get_exit_node(prev_graph)]
                    
                    # get the node in the current cfg for being connected by the previous cfg
                    curr_conn_nodes = []
                    if prev_program_type == "html":
                        curr_conn_nodes = [self.js_cfg_generator.get_entry_node(cfg)]
                    elif prev_program_type == "sh":
                        curr_conn_nodes = [self.shell_cfg_generator.get_entry_node(cfg)]
                    elif prev_program_type == "elf":
                        curr_conn_nodes = [self.bin_cfg_generator.get_entry_node(cfg.graph)]
                        
                    # update the information of the previous cfg and append the current cfg to the cfgs
                    cfgs[-1] = (prev_cfg[0], prev_cfg[1], prev_cfg[2], prev_cfg[3], prev_conn_nodes)
                    cfgs.append((program, program_type, cfg, curr_conn_nodes, []))
            
            ending_program = cfgs[-1][0] 
            reboot_keywords = path_dict[key][ending_program]["function"]["reboot"]                      
            # build the ufgs
            # also, pass the reboot lists to this function
            ufg, ufg_entry_node, ufg_reboot_nodes = self.connect_cfgs(cfgs, key, reboot_keywords)
            # it can be a three-tuple (ufg, starting node, ending node) for program slicing
            ufgs.append((ufg, ufg_entry_node, ufg_reboot_nodes))
            
        return ufgs

        
    def map_bincfg_callgraph(self, cfg_info):
        program, program_type, cfg, called_nodes, calling_nodes = cfg_info
        callgraph = self.bin_cfg_generator.get_callgraph(cfg)
        
        called_functions = self.map_bin_nodes(program, called_nodes)
        calling_functions = self.map_bin_nodes(program, calling_nodes)
        
        return (program, program_type, callgraph, called_functions, calling_functions)


    def map_bin_nodes(self, program, nodes):
        mapped_nodes = []
        bininfo_path = os.path.join(config.FW_RESULTS, "binaries.json")
        with open(bininfo_path) as f:
            bininfo = json.load(f)
        blk_func_addrs = bininfo[program]["blk_func_addrs"]
        
        for node in nodes:
            if str(node.addr) in blk_func_addrs:
                mapped_nodes = mapped_nodes + blk_func_addrs[str(node.addr)]
            
        return mapped_nodes     
        
    
    def connect_cfgs(self, cfg_list, key, reboot_keywords):
        master_graph = nx.MultiDiGraph()
        
        entry_node = None
        reboot_nodes = []
        # traverse the cfg_list
        for idx, (program, program_type, cfg, called_nodes, calling_nodes) in enumerate(cfg_list):            
            # get the reboot node from the last cfg
            if idx == len(cfg_list) - 1:
                if program_type == "html":
                    for item in reboot_keywords:
                        reboot_nodes = reboot_nodes + self.js_cfg_generator.get_node_by_str(cfg, item)
                elif program_type == "sh":
                    for item in reboot_keywords:
                        reboot_nodes = reboot_nodes + self.shell_cfg_generator.get_node_by_str(cfg, item)
                elif program_type == "elf":
                    for item in reboot_keywords:
                        reboot_nodes = reboot_nodes + self.bin_cfg_generator.get_node_reboot(program, cfg, item)
                    reboot_nodes = self.map_bin_nodes(program, reboot_nodes) 
            
            if program_type == "elf":
                program, program_type, cfg, called_nodes, calling_nodes = self.map_bincfg_callgraph((program, program_type, cfg, called_nodes, calling_nodes))
                cfg_list[idx] = (program, program_type, cfg, called_nodes, calling_nodes)
            
            # get the starting node from the first cfg
            if idx == 0:
                # implement the method to find entry node for each type of cfg
                if program_type == "html":
                    entry_node = self.js_cfg_generator.get_entry_node(cfg)
                elif program_type == "sh":
                    entry_node = self.shell_cfg_generator.get_entry_node(cfg)
                elif program_type == "elf":
                    entry_node = self.bin_cfg_generator.get_entry_node(cfg)
            
            for node in cfg:
                cfg.nodes[node]['program'] = program
                cfg.nodes[node]['type'] = program_type
            master_graph = nx.compose(master_graph, cfg)
        
        # Connect calling nodes of one CFG to called nodes of the next CFG
        for i in range(len(cfg_list) - 1):
            current_program_type = cfg_list[i][1]
            next_program_type = cfg_list[i + 1][1]
            
            current_calling_nodes = []
            next_called_nodes = []
            current_calling_nodes = cfg_list[i][4]  # Calling nodes of current CFG
        
            next_called_nodes = cfg_list[i + 1][3]  # Called nodes of next CFG

            for calling_node in current_calling_nodes:
                for called_node in next_called_nodes:
                    master_graph.add_edge(calling_node, called_node)
        
        # save the ufg in a pickle file
        save_name = 'ufg-'+key.split("/")[-1].split(".")[0]+'.pkl'
        save_path = os.path.join(config.UFG_RESULTS, save_name)
        
        print("----UFG stored at:", save_path)
        
        with open(save_path, 'wb') as f:
            pickle.dump(master_graph, f)
        
        return master_graph, entry_node, list(set(reboot_nodes))
    
        
    def program_explore(self, node, timeout=60):
        start_time = time.time()
        
        def check_timeout():
            return time.time() - start_time > timeout
    
        # From the entry node, to analyze each program and search for the IPC
        if Utils.fetch_file(node.path, ['.htm', '.html', '.shtml', '.asp']):
            self.web_call(node)
        elif Utils.fetch_file(node.path, ['sh']):
            self.shell_call(node)
        elif Utils.fetch_file(node.path, ['elf']):
            self.binary_call(node)
            
        # whenever find the reboot or firmware flash functionalities, stop exploration
        if node.functions['reboot'] != []: #TODO: CONSIDER WHEATHER ADD WRITEor node.functions['write'] != []: 
            global find_path
            find_path = 1
            update_path, entry_node = node.get_path()
            
            # Store the results in the results.json, when there are multiple paths, add a random number to the path name   
            results_path = os.path.join(config.FW_RESULTS, "results.json")
            with open(results_path, 'r') as f:
                results_dict = json.load(f)

            if not results_dict[entry_node.filetype][entry_node.path]:
                results_dict[entry_node.filetype][entry_node.path] = update_path

            elif results_dict[entry_node.filetype][entry_node.path]:
                idx = random.randint(1, 100)
                while entry_node.path+"-"+str(idx) in results_dict[entry_node.filetype].keys():
                    idx = random.randint(1, 100)
                results_dict[entry_node.filetype][entry_node.path+"-"+str(idx)] = update_path

            with open(results_path, 'w') as f:
                json.dump(results_dict, f)
                
            return
        
        if check_timeout():
            return
        

    def binary_call(self, node):
        filepath = node.path

        bininfo_path = os.path.join(config.FW_RESULTS, "binaries.json")
        webinfo_path = os.path.join(config.FW_RESULTS, "webinfo.json")
        shell_path = os.path.join(config.FW_RESULTS, "shells.json")

        with open(bininfo_path, 'r') as f:
            bin_dict = json.load(f)

        with open(webinfo_path, 'r') as fw:
            web_dict = json.load(fw)
        
        with open(shell_path, 'r') as fs:
            shell_dict = json.load(fs)

        if node.keywords:
            keywords = node.keywords['para']+node.keywords['func']
        else:
            keywords = []   
        if filepath not in bin_dict:
            self.binary_parser.ghidra_analysis(filepath, keywords)
            with open(bininfo_path, 'r') as f:
                bin_dict = json.load(f)
        

        functypes = ['delivery', 'checksum', 'device', 'version', 'signature', 'reboot', 'write']
        for functype in functypes:
            if bin_dict[filepath][functype]:
                node.functions[functype] = node.functions[functype] + bin_dict[filepath][functype]

        filetypes = ["sh"] 
        for filetype in filetypes:
            if filetype == "html":
                check_dict = web_dict
            elif filetype == "sh":
                check_dict = shell_dict
            else:
                check_dict = bin_dict
            for path in bin_dict[filepath]['call'][filetype]:
                if path in check_dict:
                    continue
                filename = path.split("/")[-1]
                if filename in usualCommands:
                    continue
                new_node = Node(node, path, filetype, "invocation")
                if not self.check_redundant(new_node):
                    node.calls.append(new_node)
                    self.program_explore(new_node)


    def web_call(self, node):
        calls = []

        traverse_path = os.path.join(config.FW_RESULTS, "traverse.json")
        with open(traverse_path, 'r') as f:
            files = json.load(f)

        webinfo_path = os.path.join(config.FW_RESULTS, "webinfo.json")
        filepath = node.path

        with open(webinfo_path, 'r') as f:
            web_dict = json.load(f)
        
        if filepath not in web_dict:
            web_info = self.web_parser.parse(filepath)
            web_dict[filepath] = web_info
            with open(webinfo_path, 'w') as f:
                json.dump(web_dict, f)

        if node.filetype == 'html':
            self.js_parser.jsFromHtml(filepath)
            if os.path.isfile(os.path.join(config.FW_RESULTS, "js.json")):
                with open(os.path.join(config.FW_RESULTS, "js.json"), 'r') as f:
                    js_info = json.load(f)
                functypes = ['delivery', 'checksum', 'device', 'version', 'signature', 'reboot', 'write']
                for callpath in js_info.keys():
                    if callpath == node.path:
                        for functype in functypes:
                            for func in js_info[callpath]:
                                if functype in js_info[callpath][func]:
                                    node.functions[functype] = node.functions[functype] + js_info[callpath][func][functype]

        # analyze the direct calls
        for item in web_dict[filepath]['call']:
            if web_dict[filepath]['call'][item] != []:
                if item == 'js':
                    try:
                        self.js_parser.jsFromHtml(filepath)
                    except Exception as e:
                        print(traceback.format_exc())
                elif item != 'lua' or item != 'php':
                    for path in web_dict[filepath]['call'][item]:
                        filename = path.split("/")[-1]
                        if filename in usualCommands:
                            continue
                        new_node = Node(node, path, item, "invocation")
                        if not self.check_redundant(new_node):
                            node.calls.append(new_node)
                            self.program_explore(new_node)
                        calls.append(path)
                        
        # analyze the indirect calls by ipc patterns
        ipc_funcs = []
        ipc_paras = []
        for item in web_dict[filepath]['ipc']:
            if web_dict[filepath]['ipc'][item] != []:
                if item == 'action' or item == 'jsfunc':
                    ipc_funcs = ipc_funcs + web_dict[filepath]['ipc'][item]
                else:
                    ipc_paras = ipc_paras + web_dict[filepath]['ipc'][item]
                
        elf_dict = self.binary_parser.get_binhandler(files['elf'], set(ipc_paras), set(ipc_funcs), set())
        elfs = list(elf_dict.keys())

        sh_dict = self.shell_parser.get_shellhandler(files['sh'], set(ipc_paras), set(ipc_funcs), set())
        shs = list(sh_dict.keys())

        # maybe add ipc between htmls/asps
        for path in elfs:
            if path not in calls:
                filename = path.split("/")[-1]
                if filename in usualCommands:
                    continue
                new_node = Node(node, path, 'elf', 'IPC', elf_dict[path])
                if not self.check_redundant(new_node):
                    node.calls.append(new_node)
                    self.program_explore(new_node)
                calls.append(path)

        for path in shs:
            if path not in calls:
                filename = path.split("/")[-1]
                if filename in usualCommands:
                    continue
                new_node = Node(node, path, 'sh', 'IPC', sh_dict[path])
                if not self.check_redundant(new_node):
                    node.calls.append(new_node)
                    self.program_explore(new_node)
                calls.append(path)
            

    def shell_call(self, node):
        filepath = node.path
        if node.caller == None:
            callpath = ''
        else:
            callpath = node.caller.path

        sh_results = shell_results(filepath, callpath)
    
        functypes = ['delivery', 'checksum', 'device', 'version', 'signature', 'reboot', 'write']
        for functype in functypes:
            for block in sh_results[filepath]:
                if block != 'metadata': 
                    if sh_results[filepath][block][functype]:
                        node.functions[functype] = node.functions[functype] + sh_results[filepath][block][functype]
            
            for dep in sh_results[filepath]['main']['depfunctions']:
                for func in sh_results[filepath]['main']['depfunctions'][dep]:
                    if sh_results[dep][func][functype]:
                        node.functions[functype] = node.functions[functype] + sh_results[dep][func][functype]

                    for intCall in sh_results[dep][func]['intercalls']:
                        if sh_results[dep][intCall][functype]:
                            node.functions[functype] = node.functions[functype] + sh_results[dep][intCall][functype]

            for extCall in sh_results[filepath]['main']['extercalls']:
                for file in sh_results:
                    for block in sh_results[file]:
                        if extCall == block:
                            if sh_results[file][block][functype]:
                                node.functions[functype] = node.functions[functype] + sh_results[file][block][functype]

                            for intCall in sh_results[file][block]['intercalls']:
                                if sh_results[file][intCall][functype]:
                                    node.functions[functype] = node.functions[functype] + sh_results[file][intCall][functype]			

        filetypes = ["sh", "elf"] 
        for filetype in filetypes:
            for path in sh_results[filepath]['main'][filetype]:
                filename = path.split("/")[-1]
                if filename in usualCommands:
                    continue
                new_node = Node(node, path, filetype, "invocation")
                if not self.check_redundant(new_node):
                    node.calls.append(new_node)
                    self.program_explore(new_node)
            
            for block in sh_results[filepath]['main']['intercalls']:
                for path in sh_results[filepath][block][filetype]:
                    filename = path.split("/")[-1]
                    if filename in usualCommands:
                        continue
                    new_node = Node(node, path, filetype, "invocation")
                    if not self.check_redundant(new_node):
                        node.calls.append(new_node)
                        self.program_explore(new_node)


    def check_redundant(self, node):
        current_node = node
        current_path = node.path
        # check whether the file has been analyzed before
        while True:
            if current_node.caller == None:
                break
            elif current_node.caller.path == current_path:
                return True
            else:
                current_node = current_node.caller
        return False
