#!/usr/bin/env bash
#
# This file is generated by l2tdevtools update-dependencies.py any dependency
# related changes should be made in dependencies.ini.

# Exit on error.
set -e

# Dependencies for running dfvfs-snippets, alphabetized, one per line.
# This should not include packages only required for testing or development.
PYTHON3_DEPENDENCIES="libbde-python3
                      libewf-python3
                      libfsapfs-python3
                      libfsext-python3
                      libfshfs-python3
                      libfsntfs-python3
                      libfsxfs-python3
                      libfvde-python3
                      libfwnt-python3
                      libluksde-python3
                      libmodi-python3
                      libqcow-python3
                      libsigscan-python3
                      libsmdev-python3
                      libsmraw-python3
                      libvhdi-python3
                      libvmdk-python3
                      libvsgpt-python3
                      libvshadow-python3
                      libvslvm-python3
                      python3-cffi
                      python3-cryptography
                      python3-dfdatetime
                      python3-dfvfs
                      python3-dtfabric
                      python3-idna
                      python3-pytsk3
                      python3-pyxattr
                      python3-pyyaml";

# Additional dependencies for running tests, alphabetized, one per line.
TEST_DEPENDENCIES="python3-mock
                   python3-pbr
                   python3-setuptools
                   python3-six";

# Additional dependencies for development, alphabetized, one per line.
DEVELOPMENT_DEPENDENCIES="pylint";

# Additional dependencies for debugging, alphabetized, one per line.
DEBUG_DEPENDENCIES="libbde-debuginfo
                    libbde-python3-debuginfo
                    libewf-debuginfo
                    libewf-python3-debuginfo
                    libfsapfs-debuginfo
                    libfsapfs-python3-debuginfo
                    libfsext-debuginfo
                    libfsext-python3-debuginfo
                    libfshfs-debuginfo
                    libfshfs-python3-debuginfo
                    libfsntfs-debuginfo
                    libfsntfs-python3-debuginfo
                    libfsxfs-debuginfo
                    libfsxfs-python3-debuginfo
                    libfvde-debuginfo
                    libfvde-python3-debuginfo
                    libfwnt-debuginfo
                    libfwnt-python3-debuginfo
                    libluksde-debuginfo
                    libluksde-python3-debuginfo
                    libmodi-debuginfo
                    libmodi-python3-debuginfo
                    libqcow-debuginfo
                    libqcow-python3-debuginfo
                    libsigscan-debuginfo
                    libsigscan-python3-debuginfo
                    libsmdev-debuginfo
                    libsmdev-python3-debuginfo
                    libsmraw-debuginfo
                    libsmraw-python3-debuginfo
                    libvhdi-debuginfo
                    libvhdi-python3-debuginfo
                    libvmdk-debuginfo
                    libvmdk-python3-debuginfo
                    libvsgpt-debuginfo
                    libvsgpt-python3-debuginfo
                    libvshadow-debuginfo
                    libvshadow-python3-debuginfo
                    libvslvm-debuginfo
                    libvslvm-python3-debuginfo";

sudo dnf install -q dnf-plugins-core
sudo dnf copr -q -y enable @gift/dev
sudo dnf install -q -y ${PYTHON3_DEPENDENCIES}

if [[ "$*" =~ "include-debug" ]]; then
    sudo dnf install -q -y ${DEBUG_DEPENDENCIES}
fi

if [[ "$*" =~ "include-development" ]]; then
    sudo dnf install -q -y ${DEVELOPMENT_DEPENDENCIES}
fi

if [[ "$*" =~ "include-test" ]]; then
    sudo dnf install -q -y ${TEST_DEPENDENCIES}
fi
