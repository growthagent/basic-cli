# Shared between tests.sh and ci/all_tests.sh so the "what to skip" rule lives
# in one place instead of drifting between the two runners.
#
# Helper files (named *-helper.roc) are spawned as subprocesses by other tests,
# not run standalone. Running one directly would hang, because it waits to be
# killed by its parent test.
is_helper_test() {
    case "$(basename "$1")" in
        *-helper.roc) return 0 ;;
        *) return 1 ;;
    esac
}
