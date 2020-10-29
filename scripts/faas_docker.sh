#!/bin/bash

#                        openNetVM
#                https://sdnfv.github.io
#
# OpenNetVM is distributed under the following BSD LICENSE:
#
# Copyright(c)
#       2015-2018 George Washington University
#       2015-2018 University of California Riverside
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
# * The name of the author may not be used to endorse or promote
#   products derived from this software without specific prior
#   written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

while getopts :d:c:D:h:o:n: OPTION ; do
    case ${OPTION} in
        d) DIR="${OPTARG}" ;;
        c) CMD=${OPTARG} ;;
        D) RAW_DEVICES=${OPTARG} ;;
        h) HUGE=${OPTARG} ;;
        o) ONVM=${OPTARG} ;;
        n) NAME=${OPTARG} ;;
        \?) echo "Unknown option -$OPTARG" && exit 1
    esac
done

DEVICES=()

if [[ "${NAME}" == "" ]] ; then
    echo -e "sudo ./docker.sh -h HUGEPAGES -n NAME [-D DEVICES] [-d DIRECTORY] [-c COMMAND]\n"
    echo -e "\te.g. sudo ./docker.sh -h /hugepages -o /root/openNetVM -n Basic_Monitor_NF -D /dev/uio0,/dev/uio1"
    echo -e "\t\tThis will create a container with two NIC devices, uio0 and uio1,"
    echo -e "\t\thugepages mapped from the host's /hugepage directory and openNetVM"
    echo -e "\t\tmapped from /root/openNetVM and it will name it Basic_Monitor_NF"
    exit 1
fi

IFS=','
for DEV in ${RAW_DEVICES} ; do
    DEVICES+=("--device=$DEV:$DEV")
done

if [[ "${DIR}" != "" ]] ; then
    DIR="--volume=${DIR}:/$(basename "${DIR}")"
fi

if [[ "${NAME}" == "master" ]] ; then
    sudo docker run \
        --ipc=host \
        --interactive --tty \
        --privileged \
        --name=master \
        --hostname=master \
        --network bridge \
        --volume=/sys/bus/pci/drivers:/sys/bus/pci/drivers \
        --volume=/dev:/dev \
        --volume=/sys/devices/system/node:/sys/devices/system/node \
        --volume=/var/run:/var/run \
        --volume=/dev/hugepages:/dev/hugepages \
        ${DIR} \
        "${DEVICES[@]}" \
        ch8728847/nfvnice:test \
        /app/onvm/go.sh -k 0 -n 0xF0 -s stdout -m 0,1,2,3 -c
else
    # warn users about go script ignoring manager checks
    echo "Please ensure the manager is running before starting dockerized NFs"
    #shellcheck disable=SC2086
    if [[ "${CMD}" == "" ]] ; then
        sudo docker run \
            --ipc=host \
            --interactive --tty \
            --privileged \
            --name="${NAME}" \
            --hostname="${NAME}" \
            --network bridge \
            --volume=/sys/bus/pci/drivers:/sys/bus/pci/drivers \
            --volume=/dev:/dev \
            --volume=/sys/devices/system/node:/sys/devices/system/node \
            --volume=/var/run:/var/run \
            --volume=/dev/hugepages:/dev/hugepages \
            ${DIR} \
            "${DEVICES[@]}" \
            ch8728847/nfvnice:test \
            /bin/bash
    else
        sudo docker run \
            --ipc=host \
            --detach=true \
            --privileged \
            --name="${NAME}" \
            --hostname="${NAME}" \
            --network bridge \
            --volume=/sys/bus/pci/drivers:/sys/bus/pci/drivers \
            --volume=/dev:/dev \
            --volume=/sys/devices/system/node:/sys/devices/system/node \
            --volume=/var/run:/var/run \
            --volume=/dev/hugepages:/dev/hugepages \
            ${DIR} \
            "${DEVICES[@]}" \
            ch8728847/nfvnice:test \
            /bin/bash -c "${CMD}"
    fi
fi

