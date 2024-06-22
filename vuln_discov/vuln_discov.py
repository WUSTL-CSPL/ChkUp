import json
import os
import configs.analysis_config as config
import yaml


class VulnDiscov:
    """
    Combine the information from string matching and function matching for vulnerability discovery
    """
    def __init__(self):
        self.vuln_results = {}
        self.vuln_results["Proper"] = []
        self.vuln_results["Improper"] = []
        self.vuln_results["Missing"] = []
    

    # Should check whether the matched functions are vulnerable or not based on the defined criteria
    def run(self):
        sim_result_path = os.path.join(config.SIM_RESULTS, "results.json")
        with open(sim_result_path, 'r') as f:
            ver_dict = json.load(f)

        vuln_func_config = config.CORPUS_CONFIG
        if not os.path.exists(vuln_func_config):
            print("The corpus configuration file does not exist!")
            return

        with open(vuln_func_config, "r") as f:
            corpus_config = yaml.safe_load(f)
        
        all_funcs = {}
        for bin_path, funcs in corpus_config["target_funcs"].items():
            funcs = {item.split(":")[1]:item.split(":")[1:] for item in funcs}
            all_funcs.update(funcs)

        ver_types = []
        log_string = ""
        for program in ver_dict:
            for func_addr in ver_dict[program].keys():
                if func_addr in all_funcs.keys():
                    ver_types.append(all_funcs[func_addr])
                    func_details = {
                        "Program": program,
                        "Function Address": func_addr,
                        "Function Name": all_funcs[func_addr][0],
                        "Verification Method": all_funcs[func_addr][1],
                        "Category": all_funcs[func_addr][2]
                    }
                    if "Improper" in str(all_funcs[func_addr]):
                        self.vuln_results["Improper"].append(func_details)
                        message = "!!!!Vulnerable verification procedures:" + program + " - " + str(ver_dict[program][func_addr]) +" - "+str(all_funcs[func_addr])
                        print(message)
                        log_string += message + "\n"
                    else:
                        self.vuln_results["Proper"].append(func_details)
                        message = "----Proper verification procedures:" + program + " - " + str(ver_dict[program][func_addr]) +" - "+str(all_funcs[func_addr])
                        log_string += message + "\n" 
        
        for proc in ["Authenticity", "Integrity", "Freshness", "Compatibility"]:
            found = any(proc in str(item) for item in ver_types)
            if not found:
                self.vuln_results["Missing"].append({
                    "Program": None,
                    "Function Address": None,
                    "Function Name": None,
                    "Verification Method": None,
                    "Category": "Missing_" + proc
                })
                message = "!!!!No verification procedures found for " + proc
                print(message)
                log_string += message + "\n"
        
        save_path = os.path.join(config.VULN_RESULTS, "vuln_discov.log")
        with open(save_path, "w") as f:
            f.write(log_string)

        results_path = os.path.join(config.VULN_RESULTS, "results.json")
        with open(results_path, "w") as f:
            json.dump(self.vuln_results, f, indent=4) 
