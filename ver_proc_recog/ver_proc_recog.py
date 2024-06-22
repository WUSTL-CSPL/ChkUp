
from ver_proc_recog.score_calculation import FunctionMatcher
from ver_proc_recog.dfg_isomorphism import DFGMatcher
import configs.analysis_config as config
import os
import json
from collections import OrderedDict


class VerProcRecog:
    
    def __init__(self):
        self.function_matcher = FunctionMatcher()
        self.dfg_matcher = DFGMatcher()
    
    def run(self):
        image_path = config.ROOT_PATH
        results_path = os.path.join(config.FW_RESULTS, "results.json")
        with open(results_path, 'r') as f:
            path_dict = json.load(f)

        path_dict = OrderedDict(path_dict)
        
        elfs = []
        
        for entry_type in path_dict:
            for key in path_dict[entry_type]:
                for program in path_dict[entry_type][key]:
                    program_type = path_dict[entry_type][key][program]["filetype"]
                    if program_type == "elf":
                        elfs.append(program)
        image_elfs = [(image_path, elfs)]

        self.function_matcher.preprocess_images(image_elfs)
        self.function_matcher.match_funcs(image_elfs, config.SIM_RESULTS, config.CORPUS_CONFIG)  
        
        func_dict = self.dfg_matcher.preprocess_data()
        ver_dict = {}
        if func_dict:
            ver_dict = self.dfg_matcher.match_graph(func_dict)
        
        sim_result_path = os.path.join(config.SIM_RESULTS, "results.json")
        with open(sim_result_path, 'w') as f:
            json.dump(ver_dict, f, indent=4) 
            
        print("----Found verification procedures:", ver_dict)
        return ver_dict
       
    
    # Run the verification procedure recognition with passing the execution paths
    def run_with_paths(self, paths):
        image_path = config.ROOT_PATH
        elfs = []
        for path_key in paths:
            path_dict_list = paths[path_key]
            for path_dict in path_dict_list:
                program_funcs = path_dict['funcs']
                elfs.extend(list(program_funcs.keys()))
        image_elfs = [(image_path, elfs)]
        
        
        self.function_matcher.preprocess_images(image_elfs)
        self.function_matcher.match_funcs(image_elfs, config.SIM_RESULTS, config.CORPUS_CONFIG)  
        
        func_dict = self.dfg_matcher.preprocess_data()
        ver_dict = {}
        if func_dict:
            ver_dict = self.dfg_matcher.match_graph(func_dict)
        return ver_dict
