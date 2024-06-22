# ChkUp
ChkUp is a tool designed to <ins>C</ins>heck for firmware <ins>U</ins>pdate vulnerabilities. ChkUp can extract program execution paths from a firmware update procedure and identify vulnerable verification steps within that procedure. To use ChkUp, users need to run our program from the command line, providing the file paths of unpacked firmware images. The expected output comprises vulnerability identification results (i.e., vulnerable verification procedures) and intermediate structural, syntactic, and semantic analysis results for programs related to firmware updates. 


## Dependencies
- python 3.6
- java 11.0.23
- npm 6.14.4
- python packages ([requirements.txt](./requirements.txt))
- ghidra 10.1.2 (https://github.com/NationalSecurityAgency/ghidra/releases)


## Usage
1. Setup the testing environment;
2. Specify necessary paths in the config files;
3. Run ChkUp using either [main.py](./main.py) by specifying paths of the unpacked firmware and result folder:
    ```
    python main.py --firmware_path "$file_path" --results_path "./results"
    ```
    or [chkup_run.sh](./chkup_run.sh) by providing a list of unpacked firmware paths and the result storing path in the script:
    ```
    bash ./chkup_run.sh
    ```
4. Check the output and the result folder for results.

## ChkUp Workflow
### Execution Path Recovery
ChkUp first identifies the entry points for conducting updates in firmware images, then creates a UFG that captures the control flow information across programs written in different programming languages. Based on the constructed UFC, Chkup can recover the program execution paths in firmware update mechanisms.

### Verification Procedure Recognition
ChkUp can identify the essential verification procedures (authenticity, integrity, freshness, and compatibility) in firmware update mechanisms. It combines both syntactic and structural features and more sophisticated semantic features based on DFG isomorphism to recognize the verification chains in the firmware update execution paths.

### Vulnerability Discovery
ChkUp is capable of detecting both missing and improper verification vulnerabilities in firmware update procedures. With the resolved execution paths and identified verification procedures, ChkUp examines whether secure verification steps are properly implemented in these paths to uncover these vulnerabilities.

### Vulnerability Validation

Vulnerability validation requires manual efforts, while ChkUp integrates the following tools to streamline some processes. [FirmAE](https://github.com/pr0v3rbs/FirmAE) or [firmadyne](https://github.com/firmadyne/firmadyne) can be used for firmware emulation. Moreover, [Ghidra](https://github.com/NationalSecurityAgency/ghidra) and [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit) are used to patch and repack firmware images. 


## Citation
If you find our repo useful, please cite our work with the following reference:
```
@article{wu2024firmware,
  title={Your Firmware Has Arrived: A Study of Firmware Update Vulnerabilities},
  author={Wu, Yuhao and Wang, Jinwen and Wang, Yujie and Zhai, Shixuan and Li, Zihan and He, Yi and Sun, Kun and Li, Qi and Zhang, Ning},
  journal={USENIX Security Symposium},
  year={2024}
}
```


## Project structure

```
├── main.py
├── chkup_run.sh
├── configs
│   ├── analysis_config.py
│   └── vuln_corpus_config.yml
├── utilities
│   ├── corpus_generation.py
│   ├── initialize.py
│   ├── pth_utils.py
│   └── sim_utils.py
├── exec_pth_rec
│   ├── control_flows
│   │   ├── bin_cfg.py
│   │   ├── js_cfg.js
│   │   ├── js_cfg.py
│   │   └── shell_cfg.py
│   ├── jsparse
│   │   └── app
│   │       ├── controllers
│   │       │   └── codeparse.js
│   │       ├── index.js
│   │       └── routes
│   │           ├── codeparse.js
│   │           └── index.js
│   ├── binary_parser.py
│   ├── const.py
│   ├── entry_finder.py
│   ├── exec_pth_rec.py
│   ├── ghidra_analysis.py
│   ├── js_parser.py
│   ├── program_node.py
│   ├── program_slicer.py
│   ├── shell_parser.py
│   ├── shell_syntax_parser.py
│   ├── ufg_constructor.py
│   └── web_parser.py
├── ver_proc_recog
│   ├── features
│   │   ├── __init__.py
│   │   ├── asm.py
│   │   ├── asm_const.py
│   │   ├── cfg.py
│   │   ├── cg.py
│   │   ├── data.py
│   │   ├── feature_manager.py
│   │   └── functype.py
│   ├── dfg_isomorphism.py
│   ├── feature_extraction.py
│   ├── ghidra_analysis_feature.py
│   ├── score_calculation.py
│   └── ver_proc_recog.py
├── vuln_discov
│   └── vuln_discov.py
└── vuln_val
    ├── poc_creation
    │   ├── modify_hex.sh
    ├── FirmAE
    ├── firmware-analysis-toolkit
    ├── firmware-mod-kit
    └── vuln_val.py
```
