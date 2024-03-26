#!/bin/sh

source /lib/svc/share/smf_include.sh
if [ -z "$SMF_FMRI" ]; then
    echo "This script can only be invoked by smf(5)"
    exit $SMF_EXIT_ERR_NOSMF
fi

function usage {
    echo "usage: $0 -c CONTRACT"
    echo
    echo "  -c CONTRACT   Contract of parent ctrun"
    echo
    echo "When called with the contract number of a ctrun parent, sends"
    echo "SIGUSR1 to the child PID of that ctrun process"
    exit $SMF_EXIT_ERR_FATAL
}

function main {
    set -x
    CONTRACT=""
    while getopts "c:" o; do
      case "${o}" in
        c)
          CONTRACT="$OPTARG"
          ;;
        *)
          usage
          ;;
      esac
    done

    [[ -n "$CONTRACT" ]] || usage
    PARENT_PID=$(pgrep -c "$CONTRACT")
    [[ -n "$PARENT_PID" ]] || exit $SMF_EXIT_ERR_FATAL
    CHILD_PID=$(pgrep -P "$PARENT_PID")
    [[ -n "$CHILD_PID" ]] || exit $SMF_EXIT_ERR_FATAL
    kill -USR1 "$CHILD_PID" || exit $SMF_EXIT_ERR_FATAL
}

main "$@"
