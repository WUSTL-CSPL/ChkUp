import configs.analysis_config as config
import os
import pickle
import angr


def generate_dfg(binary_path, addr_str_list):
    
    for addr_str in addr_str_list:
        # Initialize the project
        proj = angr.Project(binary_path, auto_load_libs=False) 

        # Generate CFG with normalization
        cfg = proj.analyses.CFG(normalize=True) # type: ignore
                
        save_path = os.path.join(config.DFG_CORPUS, addr_str+".pkl")
            
        addr = int(addr_str, 16)
        dfg = proj.analyses.VFG(
            cfg,
            start=addr,
            context_sensitivity_level=1,
            interfunction_level=1,
            record_function_final_states=True,     
        ) # type: ignore
        
        
        with open(save_path, 'wb') as f:
            pickle.dump(dfg, f)
        
        
if __name__ == '__main__':
    generate_dfg("/home/chkup/Desktop/cases/unpacked_dataset/tp-link/CVE-2022-46139/_wr940nv4_us_3_16_9_up_boot_160617_.bin.extracted/squashfs-root/usr/bin/httpd", ["004e80e8", "004e80f8"])
