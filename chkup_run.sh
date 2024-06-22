#!/bin/bash

# Initialize the JavaScript parser
is_npm_script_running() {
    pgrep -fl "node.*$1" > /dev/null
}

SCRIPT_NAME="start"
SCRIPT_PATH="/home/chkup/Desktop/ChkUp/exec_pth_rec/jsparse"

cd "$SCRIPT_PATH" || { echo "Failed to navigate to $SCRIPT_PATH"; exit 1; }

if is_npm_script_running "$SCRIPT_NAME"; then
    echo "JS parser is already running."
else
    echo "JS parser is not running. Starting the script..."
    npm run "$SCRIPT_NAME" > /dev/null 2>&1 &
    disown
fi


# Define an array of testing firmware paths
file_paths=(
    "/home/chkup/Desktop/cases/unpacked_dataset/tp-link/CVE-2022-46139/_wr940nv4_us_3_16_9_up_boot_160617_.bin.extracted"
    "/home/chkup/Desktop/cases/unpacked_dataset/tp-link/CVE-2022-46428/_wr1043nv1_en_3_13_15_up_boot_140319_.bin.extracted"
    "/home/chkup/Desktop/cases/unpacked_dataset/tp-link/CVE-2022-46914/_wa801nv1_en_3_12_16_up_130131_.bin.extracted"
)

# Loop through the array of file paths
WORKING_DIR="/home/chkup/Desktop/ChkUp"
cd "$WORKING_DIR" || { echo "Failed to navigate to $WORKING_DIR"; exit 1; }

for file_path in "${file_paths[@]}"
do
    python main.py --firmware_path "$file_path" --results_path "./results"
done
