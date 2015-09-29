#!/bin/bash

set -xe

CASTELLAN_DIR="$BASE/new/castellan"


function generate_testr_results {
    if [ -f .testrepository/0 ]; then
        sudo .tox/functional/bin/testr last --subunit > $WORKSPACE/testrepository.subunit
        sudo mv $WORKSPACE/testrepository.subunit $BASE/logs/testrepository.subunit
        sudo /usr/os-testr-env/bin/subunit2html $BASE/logs/testrepository.subunit $BASE/logs/testr_results.html
        sudo gzip -9 $BASE/logs/testrepository.subunit
        sudo gzip -9 $BASE/logs/testr_results.html
        sudo chown jenkins:jenkins $BASE/logs/testrepository.subunit.gz $BASE/logs/testr_results.html.gz
        sudo chmod a+r $BASE/logs/testrepository.subunit.gz $BASE/logs/testr_results.html.gz
    fi
}

owner=tempest

# Set owner permissions according to job's requirements.
cd $CASTELLAN_DIR
sudo chown -R $owner:stack $CASTELLAN_DIR

testenv=functional

sudo -H -u $owner tox -e genconfig

if [ ! -d /etc/castellan ]; then
    sudo mkdir /etc/castellan
fi

sudo cp $CASTELLAN_DIR/etc/castellan/castellan-functional.conf.sample /etc/castellan/castellan-functional.conf

# Run tests
echo "Running Castellan $testenv test suite"
set +e

sudo -H -u $owner tox -e $testenv

testr_exit_code=$?
set -e

# Collect and parse results
generate_testr_results
exit $testr_exit_code
