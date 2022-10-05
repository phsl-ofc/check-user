#!/usr/bin/env bash

# Usage:
#   chmod +x install.sh
#   ./install.sh

# Created by: @LATAMSRC

url_check_user='https://raw.githubusercontent.com/NT-GIT-HUB/DataPlugin/main/user_check.py'

function download_script() {
    if [[ -e chk.py ]]; then
        service user_check stop
        rm -r chk.py
    fi

    curl -sL -o chk.py $url_check_user
    chmod +x chk.py
    clear
}

function get_version() {
    local version=$(cat chk.py | grep -Eo "__version__ = '([0-9.]+)'" | cut -d "'" -f 2)
    echo $version
}

function check_installed() {
    if [[ -e /usr/bin/checker ]]; then
        clear
        echo 'CheckUser Ja esta instalado'
        read -p 'Deseja desinstalar? [s/n]: ' choice

        if [[ $choice =~ ^[Ss]$ ]]; then
            service user_check stop 1>/dev/null 2>&1
            checker --uninstall 1>/dev/null 2>&1
            rm -rf chk.py 1>/dev/null 2>&1
            echo 'CheckUser desinstalado com sucesso'
        fi
    fi
}

function main() {
    check_installed
    download_script

    if ! [ -f /usr/bin/python3 ]; then
        echo 'Installing Python3...'
        sudo apt-get install python3
    fi

    read -p 'Qual porta deseja usar?:' -e -i 5000 port

    python3 chk.py --create-service --create-executable --enable-auto-start --port $port --start $mode
}
main $@
