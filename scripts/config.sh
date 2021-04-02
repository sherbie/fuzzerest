#! /bin/bash

# Install pre-push test suite hook and radamsa fuzzer

cd "$(dirname "$0")"

echo -n "checking dependencies ... "

if ! [ -x "$(command -v python3)" ]; then
    echo "python3 is required"
    exit 1
fi

if ! [ -x "$(command -v pip3)" ]; then
    echo "pip3 is required"
    exit 1
fi

echo "done"

testhooktype="pre-push"
testhook="../.git/hooks/$testhooktype"
testcmd="PYTHONPATH=$(pwd) VERBOSE=1 make test-all"

echo -n "setting $testhooktype hook for python unit tests ... "

echo "#!/bin/bash" > $testhook
echo $testcmd >> $testhook
chmod +x $testhook

echo "done"

echo -n "setting up radamsa fuzzer ... "

radamsa_dir=../fuzzerest/util/radamsa
rm -rf $radamsa_dir
mkdir -p $radamsa_dir
radamsa_dir=$(cd $radamsa_dir; pwd)

git clone --depth 1 --branch v0.6 https://gitlab.com/akihe/radamsa $radamsa_dir

# Build radamsa
echo -n "setting up radamsa fuzzer ... "
USR_BIN_OL=$radamsa_dir/bin/ol make -s -C $radamsa_dir

if [ $? -ne 0 ]; then
    echo "failed to build radamsa"
    exit 1
fi

echo "done"
