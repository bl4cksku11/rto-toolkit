#!/bin/bash

#####################################################################
# SHODAN ASSET ENUMERATOR
# by bl4cksku11
#
# Short description:
#   Simple Bash tool that enumerates a list of IPs / hostnames using the
#   Shodan CLI. Loads assets from a file (comma-separated or newline),
#   queries `shodan host` for each asset, and writes results to a
#   timestamped output file.
#
# Features:
#   - Verifies presence of the Shodan CLI and prompts to install if missing.
#   - Initializes Shodan API key (uses ~/.config/shodan/api_key or runs `shodan init`).
#   - Accepts asset lists in two formats:
#       1) Comma-separated single line:  1.2.3.4,5.6.7.8,example.com
#       2) One asset per line:
#            1.2.3.4
#            example.com
#   - Queries Shodan for each asset with `shodan host <asset>` and saves
#     the pretty-formatted output to a file: shodansearch-YYYYMMDD-HHMMSS.txt
#   - Provides friendly output messages and graceful Ctrl+C handling.
#
# Usage:
#   1. Ensure Shodan CLI is installed: `pip install shodan`
#   2. Ensure your Shodan API key is initialized:
#        - Place key at $HOME/.config/shodan/api_key
#        - or let the script run `shodan init` and enter your key when prompted
#   3. Run the script and provide the asset file name when asked.
#
# Examples of valid asset files:
#   Comma-separated:
#     111.222.111.222,222.222.111.111,example.com
#
#   Newlines:
#     111.222.111.222
#     222.222.111.111
#     example.com
#
# Output:
#   - A timestamped file named shodansearch-YYYYMMDD-HHMMSS.txt will contain
#     the `shodan host` pretty output for each queried asset.
#
# Notes & Responsible Use:
#   - Only query hosts and networks for which you have explicit permission.
#   - Misuse of Shodan/host scanning against third-party infrastructure
#     may violate laws, terms of service or client agreements.
#   - This script is provided as-is. Verify behavior in a safe/test environment.
#
# Requirements:
#   - bash (tested on common Linux environments)
#   - shodan CLI (installable via pip: `pip install shodan`)
#   - Network connectivity to Shodan API
#
# License:
#   - MIT-style / permissive (you may add a specific license header if desired)
#
# Contact / Author:
#   - bl4cksku11
#
#####################################################################

# Trap to handle Ctrl+C
trap ctrl_c INT

function ctrl_c() {
    echo -e "\n\n[!] Exiting cleanly..."
    exit 0
}

# Banner
banner() {
    clear
    echo "#############################################"
    echo "#                                           #"
    echo "#         SHODAN ASSET ENUMERATOR           #"
    echo "#               by bl4cksku11               #"
    echo "#                                           #"
    echo "#############################################"
}

# Loading animation
loading_animation(){
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while ps -p $pid &>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

check_shodan_install(){
    which shodan &>/dev/null
    if [ $? -ne 0 ]; then
        echo "[!] Shodan CLI is not installed. Please install it using 'pip install shodan'."
        exit 1
    else
        echo "[+] Shodan CLI is installed."
    fi
}

init_shodan(){
    api_key_file="$HOME/.config/shodan/api_key"

    if [ -s "$api_key_file" ]; then
        echo "[+] Shodan API Key already initialized."
    else
        echo "[!] No Shodan API Key found."
        read -p "[?] Enter your Shodan API Key: " api_key
        shodan init "$api_key"
        if [ $? -eq 0 ]; then
            echo "[+] Shodan initialized successfully!"
        else
            echo "[!] Failed to initialize Shodan. Please check your API key."
            exit 1
        fi
    fi
}

validate_assets(){
    read -p "[?] Enter the name of the file containing your assets: " asset_file
    if [ ! -f "$asset_file" ]; then
        echo "[!] File not found."
        exit 1
    fi

    asset_content=$(cat "$asset_file" | tr -d ' ')

    if echo "$asset_content" | grep -q ","; then
        IFS=',' read -ra assets <<< "$asset_content"
    elif grep -qE '^([a-zA-Z0-9.-]+|\d{1,3}(\.\d{1,3}){3})$' "$asset_file"; then
        mapfile -t assets < "$asset_file"
    else
        echo "[!] Invalid asset format. Use one of the following formats:"
        echo -e "\n111.222.111.222,222.222.111.111,111.111.222.222\nOR\n111.222.111.222\n222.222.111.111\n111.111.222.222"
        exit 1
    fi

    echo "[+] Loaded ${#assets[@]} assets successfully."
}

process_assets(){
    timestamp=$(date +%Y%m%d-%H%M%S)
    output_file="shodansearch-$timestamp.txt"
    echo "[" > "$output_file"

    first_entry=true

    for asset in "${assets[@]}"; do
        echo -e "\n[+] Querying Shodan for: $asset"
        result=$(shodan host "$asset" --format pretty 2>/dev/null)

        if [[ -n "$result" ]]; then
            if [ "$first_entry" = true ]; then
                first_entry=false
            else
                echo "----------------------------" >> "$output_file"
            fi
            echo "$result" >> "$output_file"
            echo "[+] Data for $asset saved."
        else
            echo "[!] No data returned for $asset or error occurred."
        fi
    done

    echo "]" >> "$output_file"
    echo -e "\n[+] Scanning completed. Results saved to $output_file"
}

main(){
    banner
    check_shodan_install
    init_shodan
    validate_assets
    process_assets
}

main
