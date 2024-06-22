from exec_pth_rec.exec_pth_rec import ExecPthRec
from ver_proc_recog.ver_proc_recog import VerProcRecog 
from vuln_discov.vuln_discov import VulnDiscov 
from vuln_val.vuln_val import VulnVal
from utilities.initialize import Init
import configs.analysis_config as config
from utilities.pth_utils import Utils
import configs.analysis_config as config

import os
import argparse

import logging
for logger_name in logging.Logger.manager.loggerDict:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.CRITICAL)


def main(input_path, results_path="./results"):
    if os.path.isdir(input_path):
        root_paths = Utils.getRoot(input_path)
        num_root = len(root_paths)
        count = 0
        for root_path in root_paths:
            if root_path:
                if os.path.isdir(root_path):
                    config.ROOT_PATH = root_path
                    if num_root > 1 and count > 0:
                        sim_result_path = os.path.join(config.SIM_RESULTS, "results.json")
                        if os.path.exists(sim_result_path):
                            break
                        # initialize the results folder
                        init = Init(root_path, input_path, results_path, count)
                        init.init_results() 
                    else:
                        # initialize the results folder
                        init = Init(root_path, input_path, results_path)
                        init.init_results()

                    print("\n")
                    print("====================================================================")
                    print("Start analyzing the firmware:", root_path)

                    # Execution path recovery module
                    print("--------------------------------------------------------------------")
                    print("Start UFG construction...")
                    exec_pth_rec = ExecPthRec()
                    ufgs = exec_pth_rec.run()
                    print("----Execution path recovery results stored at:", config.UFG_RESULTS)
                    
                    # Verification procedure recognition
                    print("--------------------------------------------------------------------")
                    print("Start verification procedure recognition...")
                    ver_proc_recog = VerProcRecog() 
                    ver_dict = ver_proc_recog.run()
                    print("----Verification procedure recognition results stored at:", config.SIM_RESULTS)
                    
                    # Vulnerability discovery
                    print("--------------------------------------------------------------------")
                    print("Start vulnerability discovery...")
                    vuln_discov = VulnDiscov()
                    vuln_discov.run()
                    print("----Vulnerability discovery results stored at:", config.SIM_RESULTS)
                    print("\n")
                    
                    count = count+1
                    
            else:
                print("Cannot find the root path!")  


if __name__=='__main__':
    parser = argparse.ArgumentParser(description="Script for analyzing firmware images using ChkUp.")

    # Add arguments
    parser.add_argument("--firmware_path", type=str, required=True, help="Path to the unpacked firmware image", dest="input_path")
    parser.add_argument("--results_path", type=str, required=True, help="Path to the results folder", dest="results_path")
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Call the main function with the parsed arguments
    main(args.input_path, args.results_path)
