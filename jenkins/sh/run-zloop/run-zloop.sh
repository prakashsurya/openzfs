#!/bin/bash

source ${JENKINS_DIRECTORY}/sh/library/common.sh

check_env ENABLE_WATCHPOINTS RUN_TIME

if [[ "$ENABLE_WATCHPOINTS" == "yes" ]]; then
    export ZFS_DEBUG="watch"
else
    export ZFS_DEBUG=""
fi

log_must mkdir /var/tmp/test_results
log_must cd /var/tmp/test_results

zloop -t $RUN_TIME -c . -f .
result=$?

if [[ $result -ne 0 ]]; then
    if [[ -r ztest.cores ]]; then
        log_must cat ztest.cores
    fi

    if [[ -r core ]]; then
        log_must echo '::status' | log_must mdb core
        log_must echo '::stack' | log_must mdb core
    fi
fi

log_must tail -n 30 ztest.out

exit $result

# vim: tabstop=4 shiftwidth=4 expandtab textwidth=72 colorcolumn=80
