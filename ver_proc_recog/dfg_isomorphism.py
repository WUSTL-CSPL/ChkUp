
import angr
import os
import pickle
import configs.analysis_config as config
from networkx.algorithms import isomorphism


class DFGMatcher:
    def __init__(self):
        self.config_fname = config.CORPUS_CONFIG.split("/")[-1].split(".")[0]
        self.sim_result_folder = os.path.join(config.SIM_RESULTS, self.config_fname)
    
    def preprocess_data(self):
        # get and parse results from the first step of matching
        if not os.path.exists(self.sim_result_folder):
            return None
        
        func_dict = {}   
        for dir in os.listdir(self.sim_result_folder):
            parts = dir.split("-")
            # target_image_idx = parts[1]
            # target_bin_name = parts[2]
            target_func_addr = parts[3] 
            target_func_name = parts[4]
            # target_bin_arch = parts[5]
            
            lines = []
            for file in os.listdir(os.path.join(self.sim_result_folder, dir)):
                if config.FW_NAME in file:
                    with open(os.path.join(self.sim_result_folder, dir, file)) as f:
                        while True:
                            line = f.readline()
                            if line == '' or len(lines) == 5:
                                break
                            lines.append(line)
                            
            for idx, line in enumerate(lines):
                scores = line.split(":::")
                scores = list(map(lambda x: x.split(","), scores))
                image_path, bin_path, func_addr, func_name, arch = scores[0]
                
                if bin_path not in func_dict:
                    func_dict[bin_path] = []
                
                func_dict[bin_path].append((func_addr, target_func_addr, target_func_name))
            
        return func_dict  
                
    # input: program - functions for DFG generation
    # output: a DFG for each function
    def match_graph(self, func_dict):
        dfg_dict = {}
        
        for program in func_dict.keys():
            dfg_dict[program] = {}
            # load the cfg of the program
            filename = program.split("/")[-1]
            graph_path = os.path.join(config.UFG_RESULTS, filename+".pkl")
            cfg = None
            if os.path.exists(graph_path):
                with open(graph_path, 'rb') as f:
                    cfg = pickle.load(f)
            if not cfg:
                continue 
            
            # check whether the dfg has been generated 
        
            proj = angr.Project(program, auto_load_libs=False)
            
            for func_addr, target_func_addr, target_func_name in func_dict[program]:
                if target_func_name in dfg_dict[program]:
                    continue
                try:
                    func_dfg = self.generate_dfg(proj, cfg, func_addr)
                    target_func_dfg = self.load_target_func_dfg(target_func_addr)# load the target_func_dfg
                    
                    is_isomorphic = self.graph_isomorphism(func_dfg, target_func_dfg)
                    
                    if is_isomorphic:
                        dfg_dict[program][target_func_name] = func_addr
                except:
                    continue
            
        return dfg_dict
    
   
    def load_target_func_dfg(self, addr_str):
        save_path = os.path.join(config.DFG_CORPUS, addr_str+".pkl")
        with open(save_path, 'rb') as f:
            dfg = pickle.load(f)
            return dfg


    def generate_dfg(self, proj, cfg, addr_str):
        dfg_dir = os.path.join(config.SIM_RESULTS, "dfg")
        save_path = os.path.join(dfg_dir, addr_str+".pkl")
        
        if os.path.exists(save_path):
            with open(save_path, 'rb') as f:
                dfg = pickle.load(f)
                return dfg
            
        addr = int(addr_str, 16)
        dfg = proj.analyses.VFG(
            cfg,
            start=addr,
            context_sensitivity_level=1,
            interfunction_level=1,
            record_function_final_states=True,     
        ) # type: ignore
        
        if not os.path.exists(dfg_dir):
            os.makedirs(dfg_dir)
        
        with open(save_path, 'wb') as f:
            pickle.dump(dfg, f)
        return dfg
        

    def graph_isomorphism(self, func_dfg, target_func_dfg):
        GM = isomorphism.DiGraphMatcher(func_dfg.graph, target_func_dfg.graph)
        return GM.is_isomorphic()
