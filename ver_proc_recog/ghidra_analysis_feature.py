import os
import subprocess

import configs.analysis_config as config
from utilities.sim_utils import do_multiprocess

import logging
import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO, logger=logger)


def ghidra_analysis(elf):
    ghidra_project = os.path.join(config.FW_RESULTS, "ghidra_project")
    if not os.path.isdir(ghidra_project):
        os.makedirs(ghidra_project)

    s = "feature_extraction"
    exec_script = config.GHIDRA_FEATURE_SCRIPT

    binpath = elf.strip('\n')
    binname = binpath.split('/')[-1]
    
    output_name = os.path.join(config.FW_RESULTS, "binaries.json") 

    project_name = binname
    ghidra_rep = os.path.join(ghidra_project, binname) + ".rep"
    ghidra_log = os.path.join(ghidra_project, binname) + ".log"

    ghidra_args = [
    config.HEADLESS_GHIDRA, ghidra_project, project_name,
    '-postscript', exec_script, output_name, config.ROOT_PATH, config.FW_RESULTS,
    '-scriptPath', os.path.dirname(exec_script)
    ]

    if os.path.exists(ghidra_rep):
        ghidra_args += ['-process', os.path.basename(binpath)]
    else:
        ghidra_args += ['-import', "'" + binpath + "'"]

    with open(ghidra_log, "w") as f:
        p = subprocess.Popen(ghidra_args, stdout=f, stderr=f)
        p.wait()


def ghidra_analysis_batch(elfs):
    logger.info("[+] start extracting {0} files ...".format(len(elfs)))
    res = do_multiprocess(
        ghidra_analysis,
        elfs,
        chunk_size=1,
        threshold=1,
        timeout=0,
        )
    logger.info("extraction done!")
    
    return res
