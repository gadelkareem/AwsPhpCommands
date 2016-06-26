#!/bin/bash
#################################
# `endec` - encrypt/decrypt tool
# author - Daniel a.k.a ViruSzZ
# url: https://stavrovski.net/blog/tool-to-easily-encrypt-decrypt-your-data-under-gnulinux
#################################

#######################
# User Configuration
# --------------------
# password used for encrypting
# or decrypting a file.
# leave blank for interactive mode
#ENC_PASS=
#######################

#######################
# Text color variables
# --------------------
txtrst='\e[0m'          # Text reset
bldylw='\e[1;33m'       # yellow
bldblu='\e[1;34m'       # blue
bldred='\e[1;31m'       # red    - Bold
txtund=$(tput sgr 0 1)  # Underline
#######################
# Feedback indicators
# --------------------
info="${bldylw}==>${txtrst}"
pass="${bldblu}***${txtrst}"
warn="${bldred}!!!${txtrst}"
#######################

#######################
# Script Functions
# --------------------
###echoes formatted/colored array to stdout
echo_info() { echo -e "${info} ${bldylw}${@}${txtrst}"; }
echo_ok() { echo -e "${pass} ${bldblu}${@}${txtrst}"; }
echo_err() { echo -e "${warn} ${bldred}${@}${txtrst}"; }
###

### check pre
check_pre()
{
    _OPENSSL=$(which openssl 2>/dev/null)
    [[ -z ${_OPENSSL} ]] && \
    echo_err "ERROR: openssl not available on the system or is not in the PATH.\n(${PATH})" && \
    exit 1
}
###

### usage fun
usage()
{
    echo -e "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    echo -e "      'endec' encryption/decryption tool"
    echo -e "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    echo
    echo -e " USAGE:      <switch>    <arg>"
    echo -e "         location  -o    /location - (optional)"
    echo -e "------------------------------------------------"
    echo -e "         encrypt   -e    /file"
    echo -e "         decrypt   -d    /file"
    echo
    echo -e "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    exit 1
}
###

### validate pass input
valid_pass()
{
    if [[ -z ${ENC_PASS} ]]
    then
        echo_ok "Enter the password you will use for (de|en)cryption?"
        echo -n Password:
        read -s ENC_PASS
        echo
        echo -n Retype:
        read -s pass2
        echo
        [[ ${ENC_PASS} != ${pass2} ]] && \
        echo_err "ERROR: passwords do not match" && exit 1
    fi
    finalPass=${ENC_PASS}
}
###

#######################
# Pre checks and stuff
#######################
[[ -z ${@} ]] && usage || check_pre
#######################
# the program starts
#######################
while getopts "o:e:d:h" option
do
    case ${option} in
        o)
            [[ $# -le 3 ]] && usage

            [[ ! -d ${OPTARG} ]] && \
            echo_info "INFO: '${OPTARG}' do not exist or is not a dir. using current working dir.." && \
            outDir=$(pwd) || outDir=${OPTARG%%/}
        ;;

        e)
            [[ ! -f ${OPTARG} ]] && \
            echo_err "ERROR: specified target '${OPTARG}' do not exist or is not a file." && \
            echo_info "INFO: run \`${0##*/} -h\` for the usage" && exit 1

            [[ -z ${outDir} ]] && outDir=$(pwd)
            outName=${OPTARG%%/}
            outName=$(echo ${outName##*/} | tr '/' '-')

            valid_pass && \
            echo_info "FILE NAME: ${outName}" && \
            echo_info "INFO: encryption started at $(date '+%Y-%m-%d %H:%M:%S')"

            ${_OPENSSL} aes-256-cbc -salt -k ${finalPass} -in ${OPTARG%%/} \
                    -out ${outDir%%/}/${outName}.enc 2>/dev/null

            [[ $? -ne 0 ]] && \
                echo_err "ERROR: error occured while encrypting..." && \
                rm -f ${outDir%%/}/${outName}.enc 2>/dev/null && exit 1

            echo_info "INFO: encryption finished at $(date '+%Y-%m-%d %H:%M:%S')"
            echo_info "SUCCESS: '${OPTARG%%/}' has been encrypted and saved as ${outDir%%/}/${outName}.enc\n"

            exit
        ;;

        d)
    [[ ! -f ${OPTARG} ]] && \
            echo_err "ERROR: specified target '${OPTARG}' do not exist or is not a file." && \
            echo_info "INFO: run \`${0##*/} -h\` for the usage" && exit 1

            [[ -z ${outDir} ]] && outDir=$(pwd)
            outName=${OPTARG%%/}
            outName=$(echo ${outName##*/} | tr '/' '-')

            valid_pass && \
            echo_info "FILE NAME: ${outName}" && \
            echo_info "INFO: decryption started at $(date '+%Y-%m-%d %H:%M:%S')"

            ${_OPENSSL} aes-256-cbc -d -salt -k ${finalPass} -in ${OPTARG} \
                   -out ${outDir%%/}/${outName%.*} 2>/dev/null

            [[ $? -ne 0 ]] && \
            echo_err "ERROR: error occured while decrypting...password not correct" && \
            rm -f ${outDir%%/}/${outName%.*} 2>/dev/null && exit 1

            echo_info "INFO: decryption finished at $(date '+%Y-%m-%d %H:%M:%S')"
            echo_info "SUCCESS: '${OPTARG}' has been decrypted as ${outDir%%/}/${outName%.*}\n"

            exit
        ;;

        h)
            usage
        ;;

        \?)
            usage
        ;;

        :)
            usage
        ;;
    esac
done