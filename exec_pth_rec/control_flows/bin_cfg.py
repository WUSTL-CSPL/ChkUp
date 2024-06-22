import angr
import time
import os
import json

import configs.analysis_config as config 

import logging
logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('claripy').setLevel(logging.CRITICAL)


class BinCFGGenerator:

    def generate_cfg(self, binary_path, load_libs=False):
        start_time = time.time()
        proj = None
        cfg = None

        try:
            # Initialize the project
            proj = angr.Project(binary_path, auto_load_libs=load_libs) 
            # Generate CFG with normalization
            cfg = proj.analyses.CFG(normalize=True) # type: ignore
            # Store the function information
            func_blk_addrs = {}
            blk_func_addrs = {}
            if cfg:
                for func_addr in cfg.kb.functions.callgraph.nodes():
                    func = cfg.kb.functions[func_addr]
                    func_blk_addrs[func_addr] = list(func.block_addrs)
                for func_addr, blk_addrs in func_blk_addrs.items():
                    for blk_addr in blk_addrs:
                        if blk_addr not in blk_func_addrs:
                            blk_func_addrs[blk_addr] = []
                        blk_func_addrs[blk_addr].append(func_addr)
            
            # store the function information in a json file
            bin_info_path = os.path.join(config.FW_RESULTS, "binaries.json")
            with open(bin_info_path) as f:
                bin_info = json.load(f)
            bin_info[binary_path]['blk_func_addrs'] = blk_func_addrs
            
            with open(bin_info_path, 'w') as f:
                json.dump(bin_info, f)

        except Exception as e:
            print(f"An error occurred: {e}")
        
        finally:
            end_time = time.time()
            duration = end_time - start_time
            return proj, cfg, duration
    
        
    def get_entry_node_proj(self, proj, cfg):
        entry_node = cfg.get_any_node(proj.entry)
        return entry_node

    def get_entry_node(self, cfg):
        for node in cfg.nodes():
            if cfg.in_degree(node) == 0:
                return node
        return None
    
    def get_callgraph(self, cfg):
        callgraph = cfg.kb.functions.callgraph
        return callgraph
    
    def get_exit_node(self, cfg):
        for node in cfg.graph.nodes():
            if len(list(cfg.graph.successors(node))) == 0:
                return node
        return None
    
    def get_node_ipc(self, program, cfg, name):
        found_nodes = []
        bininfo_path = os.path.join(config.FW_RESULTS, "binaries.json")
        with open(bininfo_path) as f:
            bininfo = json.load(f)
        ip_addrs = bininfo[program]["ipc"]
        for keyword in ip_addrs:
            if name == keyword:
                for item in ip_addrs[keyword]:
                    addr = int(ip_addrs[keyword][item], 16)
                    node = cfg.get_any_node(addr, anyaddr=True) 
                    if node:
                        found_nodes.append(node) 
        return found_nodes
                        
    def get_node_reboot(self, program, cfg, name):
        found_nodes = []
        bininfo_path = os.path.join(config.FW_RESULTS, "binaries.json")
        with open(bininfo_path) as f:
            bininfo = json.load(f)
        reboots = bininfo[program]["reboot"]
        for item in reboots:
            if name==item:
                reboot_name, reboot_addr = item.split(":")
                addr = int(reboot_addr, 16)
                node = cfg.get_any_node(addr, anyaddr=True)
                if node:
                    found_nodes.append(node)
        return found_nodes
    
    def get_node_invocation(self, program, cfg, name):
        found_nodes = []
        bininfo_path = os.path.join(config.FW_RESULTS, "binaries.json")
        with open(bininfo_path) as f:
            bininfo = json.load(f)
        if program not in bininfo:
            return found_nodes
        invocation_addrs = bininfo[program]["invocation"]
        for path in invocation_addrs:
            filename = path.split("/")[-1]
            if name==filename:
                for addr in invocation_addrs[path]:
                    addr = int(addr, 16)
                    node = cfg.get_any_node(addr, anyaddr=True)
                    if node:
                        found_nodes.append(node) #node.addr
        return found_nodes
