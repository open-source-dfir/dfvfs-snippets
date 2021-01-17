#!/usr/bin/env bash
#
# Script to install dfvfs on Ubuntu from the GIFT PPA. Set the environment
# variable GIFT_PPA_TRACK if want to use a specific track. The default is dev.
#
# This file is generated by l2tdevtools update-dependencies.py any dependency
# related changes should be made in dependencies.ini.

# Exit on error.
set -e

GIFT_PPA_TRACK=${GIFT_PPA_TRACK:-dev}

export DEBIAN_FRONTEND=noninteractive

# Dependencies for running dfvfs, alphabetized, one per line.
# This should not include packages only required for testing or development.
PYTHON_DEPENDENCIES="libbde-python3
                     libewf-python3
                     libfsapfs-python3
                     libfsext-python3
                     libfshfs-python3
                     libfsntfs-python3
                     libfsxfs-python3
                     libfvde-python3
                     libfwnt-python3
                     libluksde-python3
                     libqcow-python3
                     libsigscan-python3
                     libsmdev-python3
                     libsmraw-python3
                     libvhdi-python3
                     libvmdk-python3
                     libvshadow-python3
                     libvslvm-python3
                     python3-cffi-backend
                     python3-cryptography
                     python3-dfdatetime
                     python3-dtfabric
                     python3-idna
                     python3-pytsk3
                     python3-yaml";

# Additional dependencies for running tests, alphabetized, one per line.
TEST_DEPENDENCIES="python3-distutils
                   python3-mock
                   python3-pbr
                   python3-setuptools
                   python3-six";

# Additional dependencies for development, alphabetized, one per line.
DEVELOPMENT_DEPENDENCIES="pylint";

# Additional dependencies for debugging, alphabetized, one per line.
DEBUG_DEPENDENCIES="libbde-dbg
                    libbde-python3-dbg
                    libewf-dbg
                    libewf-python3-dbg
                    libfsapfs-dbg
                    libfsapfs-python3-dbg
                    libfsext-dbg
                    libfsext-python3-dbg
                    libfshfs-dbg
                    libfshfs-python3-dbg
                    libfsntfs-dbg
                    libfsntfs-python3-dbg
                    libfsxfs-dbg
                    libfsxfs-python3-dbg
                    libfvde-dbg
                    libfvde-python3-dbg
                    libfwnt-dbg
                    libfwnt-python3-dbg
                    libluksde-dbg
                    libluksde-python3-dbg
                    libqcow-dbg
                    libqcow-python3-dbg
                    libsigscan-dbg
                    libsigscan-python3-dbg
                    libsmdev-dbg
                    libsmdev-python3-dbg
                    libsmraw-dbg
                    libsmraw-python3-dbg
                    libvhdi-dbg
                    libvhdi-python3-dbg
                    libvmdk-dbg
                    libvmdk-python3-dbg
                    libvshadow-dbg
                    libvshadow-python3-dbg
                    libvslvm-dbg
                    libvslvm-python3-dbg";

sudo add-apt-repository ppa:gift/${GIFT_PPA_TRACK} -y
sudo apt-get update -q
sudo apt-get install -q -y ${PYTHON_DEPENDENCIES}

if [[ "$*" =~ "include-debug" ]];
then
	sudo apt-get install -q -y ${DEBUG_DEPENDENCIES}
fi

if [[ "$*" =~ "include-development" ]];
then
	sudo apt-get install -q -y ${DEVELOPMENT_DEPENDENCIES}
fi

if [[ "$*" =~ "include-test" ]];
then
	sudo apt-get install -q -y ${TEST_DEPENDENCIES}
fi
