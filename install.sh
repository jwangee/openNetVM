
# Install DPDK
git submodule sync
git submodule update --init

export ONVM_HOME=$(pwd)
export RTE_SDK=${ONVM_HOME}/dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc
export ONVM_NUM_HUGEPAGES=1024
export ONVM_NIC_PCI=""

./scripts/install.sh
