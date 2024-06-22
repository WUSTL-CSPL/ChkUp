class EntryFinder:
    def __init__(self, web_parser, shell_parser, binary_parser):
        self.web_parser = web_parser
        self.shell_parser = shell_parser
        self.binary_parser = binary_parser  

    def get_web_entry(self):
        web_entry = self.web_parser.search_entry(self.web_files)   
        return web_entry

    def get_sh_entry(self):
        shell_entry, shell_entry_score = self.shell_parser.search_entry(self.sh_files)
        return shell_entry, shell_entry_score
            
    def get_bin_entry(self):
        binary_entry, binary_entry_score = self.binary_parser.search_entry(self.bin_files)
        return binary_entry, binary_entry_score
            
    # try to find web entry, shell entry, and binary entry
    def find_update_entry(self, web_files, sh_files, bin_files):
        self.web_files = web_files  
        self.sh_files = sh_files
        self.bin_files = bin_files
        
        entry_path = self.get_web_entry()
        entry_type = 'html'

        if not entry_path:
            sh_entry_path, sh_entry_score = self.get_sh_entry()
            bin_entry_path, bin_entry_score = self.get_bin_entry()

            if sh_entry_path == None and bin_entry_path == None:
                return None, None
            
            if sh_entry_score >= bin_entry_score:
                entry_path = sh_entry_path
                entry_type = 'sh'
            else:
                entry_path = bin_entry_score
                entry_type = 'elf'
        
        return entry_path, entry_type
