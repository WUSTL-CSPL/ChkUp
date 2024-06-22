from utilities.pth_utils import Utils
from configs import analysis_config as config

from exec_pth_rec.entry_finder import EntryFinder
from exec_pth_rec.web_parser import WebParser
from exec_pth_rec.shell_parser import ShellParser
from exec_pth_rec.binary_parser import BinaryParser
from exec_pth_rec.js_parser import JSParser
from exec_pth_rec.ufg_constructor import UFGConstructor 
from exec_pth_rec.program_slicer import ProgramSlicer

import os

class ExecPthRec:
    """
    recovery the UFG
    input: update entry program; output: UFG

    explore the execution paths
    input: UFG; output: execution paths
    """
    def __init__(self):
        
        # Retrieve all files from the file system
        traverse_path = os.path.join(config.FW_RESULTS, "traverse.json")
        self.files = Utils.traverse_file(config.INPUT_PATH, traverse_path)
        self.web_files = self.files['html'] + self.files['asp'] + self.files['php']
        self.sh_files = self.files['sh']
        self.bin_files = self.files['elf']
        self.js_files = self.files['js']
        
        # Initialize the parsers
        if self.web_files:
            self.web_parser = WebParser()   
        else:
            self.web_parser = None

        if self.sh_files:
            self.shell_parser = ShellParser()
        else:
            self.shell_parser = None

        if self.bin_files:
            self.binary_parser = BinaryParser()
        else:
            self.binary_parser = None

        if self.js_files:
            self.js_parser = JSParser()
        else:
            self.js_parser = None

        # Find the update entry program
        self.entry_finder = EntryFinder(self.web_parser, self.shell_parser, self.binary_parser)
        # Recovery the UFG
        self.ufg_constructor = UFGConstructor(self.web_parser, self.js_parser, self.shell_parser, self.binary_parser)
        # Explore the execution paths
        self.program_slicer = ProgramSlicer()

    def run(self):
        entry_path, entry_type = self.entry_finder.find_update_entry(self.web_files, self.sh_files, self.bin_files)   
        print("----Entry program:", entry_path)
        ufgs = self.ufg_constructor.ufg_construct(entry_path, entry_type)

        # # Explore the execution paths
        # paths = {}
        # for ufg, ufg_entry_node, ufg_reboot_nodes in ufgs:
        #     paths = self.program_slicer.slice(ufg, ufg_entry_node, ufg_reboot_nodes)
        
        return ufgs #, paths
       