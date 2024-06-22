import configs.analysis_config as config
import os
import re

class Init:
    def __init__(self, root_path, input_path, results_path, count=None):
        config.RESULTS_DIR = results_path
        config.INPUT_PATH = input_path

        if not input_path.split("/")[-1]:
            fw_name = input_path.split("/")[-2]
        else:
            fw_name = input_path.split("/")[-1]
        config.FW_NAME = fw_name
        if count:
            self.fw_results = os.path.join(config.RESULTS_DIR, fw_name+"-"+str(count))
        else:
            self.fw_results = os.path.join(config.RESULTS_DIR, fw_name)
        
        ufg_results = os.path.join(self.fw_results, "exec_pth")
        sim_results = os.path.join(self.fw_results, "ver_proc")
        vuln_results = os.path.join(self.fw_results, "vuln_discov")
        config.UFG_RESULTS = ufg_results
        config.SIM_RESULTS = sim_results
        config.VULN_RESULTS = vuln_results
        config.FW_RESULTS = ufg_results

        with open("./configs/analysis_config.py", 'r') as f:
            config_contents = f.read()
        
        patterns = {
            r'FW_NAME = ".*?"': f'FW_NAME = "{fw_name}"',
            r'RESULTS_DIR = ".*?"': f'RESULTS_DIR = "{results_path}"',
            r'FW_RESULTS = ".*?"': f'FW_RESULTS = "{ufg_results}"',
            r'UFG_RESULTS = ".*?"': f'UFG_RESULTS = "{ufg_results}"',
            r'SIM_RESULTS = ".*?"': f'SIM_RESULTS = "{sim_results}"',
            r'VULN_RESULTS = ".*?"': f'VULN_RESULTS = "{vuln_results}"',
            r'ROOT_PATH = ".*?"': f'ROOT_PATH = "{root_path}"',  
            r'INPUT_PATH = ".*?"': f'INPUT_PATH = "{input_path}"',
        }

        for pattern, replacement in patterns.items():
            config_contents = re.sub(pattern, replacement, config_contents)

        with open("./configs/analysis_config.py", 'w') as file:
            file.write(config_contents)

    # create a series of folders and file for results store
    def init_results(self):

        if not os.path.exists(config.RESULTS_DIR):
            os.makedirs(config.RESULTS_DIR)

        if not os.path.exists(self.fw_results):
            os.makedirs(self.fw_results)
            
        if not os.path.exists(config.UFG_RESULTS):
            os.makedirs(config.UFG_RESULTS)
            
        if not os.path.exists(config.SIM_RESULTS):
            os.makedirs(config.SIM_RESULTS)

        if not os.path.exists(config.VULN_RESULTS):
            os.makedirs(config.VULN_RESULTS)
            
        traverse_path = os.path.join(config.FW_RESULTS, "traverse.json")
        webinfo_path = os.path.join(config.FW_RESULTS, "webinfo.json")
        results_path = os.path.join(config.FW_RESULTS, "results.json")
        sh_path = os.path.join(config.FW_RESULTS, "shells.json")
        binary_path = os.path.join(config.FW_RESULTS, "binaries.json")
        jsfromhtml_path = os.path.join(config.FW_RESULTS, "jsfromhtml.json")
        
        if not os.path.exists(webinfo_path):
            with open(webinfo_path, 'w') as f:
                f.write("{}")

        if not os.path.exists(sh_path):
            with open(sh_path, 'w') as f:
                f.write("{}")
        
        if not os.path.exists(binary_path):
            with open(binary_path, 'w') as f:
                f.write("{}")

        if not os.path.exists(results_path):
            with open(results_path, 'w') as f:
                f.write("{}")

        if not os.path.exists(jsfromhtml_path):
            with open(jsfromhtml_path, 'w') as f:
                f.write("{}")
