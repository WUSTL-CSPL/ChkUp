import subprocess

class VulnVal:
    def __init__(self):
        self.firmae_init_path = "./FirmAE/init.sh"
        self.firmae_run_path = "./FirmAE/run.sh"
        
        self.fat_run_path = "./firmware-analysis-toolkit/fat.py"
        self.fat_reset_path = "./firmware-analysis-toolkit/reset.py"


    def run_fat(self, firmware_path):
        subprocess.run(["python", self.fat_reset_path])
        subprocess.run(["python", self.fat_run_path, firmware_path])


    def run_firmae(self, brand, firmware_path):
        subprocess.run(["sh", self.firmae_init_path])
        subprocess.run(["sh", self.firmae_run_path, "-r", brand, firmware_path])