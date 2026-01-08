app [main!] { pf: platform "../platform/main.roc" }

import pf.Stdout
import pf.Cmd
import pf.Arg exposing [Arg]
import pf.Sleep

# Integration test for PR_SET_PDEATHSIG behavior.
#
# PR_SET_PDEATHSIG ensures that when a parent process dies, children
# spawned via spawn_grouped! automatically receive SIGKILL.
#
# NOTE: This test only works on Linux. PR_SET_PDEATHSIG is Linux-specific.
# On other platforms, this test will skip gracefully.
#
# Test strategy:
# 1. Build a helper that spawns "sleep 9999" via spawn_grouped!
# 2. Run helper, wait for child to appear
# 3. Kill helper with SIGKILL
# 4. Verify "sleep 9999" also died

main! : List Arg => Result {} _
main! = |_args|
    # Platform check: skip on non-Linux
    when check_platform!({}) is
        Err(NotLinux(platform)) ->
            Stdout.line!("SKIP: PR_SET_PDEATHSIG test only runs on Linux (detected: ${platform})")
        Ok({}) ->
            run_pdeathsig_test!({})

run_pdeathsig_test! : {} => Result {} _
run_pdeathsig_test! = |{}|
    # Clean up any leftover processes from previous runs
    _ = Cmd.new("pkill") |> Cmd.args(["-9", "-f", "sleep 9999"]) |> Cmd.exec_output!()
    _ = Cmd.new("pkill") |> Cmd.args(["-9", "-f", "pdeathsig-helper"]) |> Cmd.exec_output!()
    Sleep.millis!(100)

    # Build the helper
    Stdout.line!("Building helper...")?
    build_result = Cmd.new("roc")
        |> Cmd.args(["build", "--linker", "legacy", "tests/pdeathsig-helper.roc", "--output", "tests/pdeathsig-helper"])
        |> Cmd.exec_output!()

    when build_result is
        Ok(_) -> {}
        Err(e) ->
            Stdout.line!("Build failed: ${Inspect.to_str(e)}")?
            Err(BuildFailed)?

    # Start the helper in background using spawn! (not spawn_grouped!)
    # We use spawn! here because we want to test that the HELPER's use of
    # spawn_grouped! causes its child to die when we kill the helper.
    # Using spawn_grouped! here would confuse what we're testing.
    Stdout.line!("Starting helper...")?
    _ = Cmd.new("tests/pdeathsig-helper") |> Cmd.spawn!()?

    # Poll for child (sleep 9999) to appear (avoid race condition with fixed sleep)
    child_pid = poll_for_sleep_pid!(50)?  # 50 attempts * 100ms = 5s timeout

    Stdout.line!("Found child PID: ${Num.to_str(child_pid)}")?

    # Find and kill the helper with SIGKILL
    helper_pid = find_helper_pid!({})?
    Stdout.line!("Killing helper (PID ${Num.to_str(helper_pid)}) with SIGKILL...")?

    # Kill helper - ignore result (might already be dead)
    _ = Cmd.new("kill")
        |> Cmd.args(["-9", Num.to_str(helper_pid)])
        |> Cmd.exec_output!()

    # Poll for child death (avoid fixed sleep race condition)
    child_died = poll_for_child_death!(child_pid, 50)?  # 50 attempts * 100ms = 5s timeout

    if child_died then
        Stdout.line!("PASS: Child died when parent was killed (PR_SET_PDEATHSIG works)")
    else
        # Clean up
        _ = Cmd.new("kill") |> Cmd.args(["-9", Num.to_str(child_pid)]) |> Cmd.exec_output!()
        Stdout.line!("FAIL: Child survived! PR_SET_PDEATHSIG not working.")?
        Err(PdeathsigFailed)

## Poll for "sleep 9999" to appear, with retries
poll_for_sleep_pid! : U64 => Result I64 _
poll_for_sleep_pid! = |max_attempts|
    poll_for_sleep_loop!(max_attempts, 0)

poll_for_sleep_loop! : U64, U64 => Result I64 _
poll_for_sleep_loop! = |max_attempts, attempt|
    if attempt >= max_attempts then
        Err(FailedExpectation("sleep 9999 process did not appear after ${Num.to_str(max_attempts)} attempts"))
    else
        when try_find_sleep_pid!({}) is
            Ok(pid) -> Ok(pid)
            Err(_) ->
                Sleep.millis!(100)
                poll_for_sleep_loop!(max_attempts, attempt + 1)

## Try to find "sleep 9999" PID (returns error if not found)
try_find_sleep_pid! : {} => Result I64 [NotFound]
try_find_sleep_pid! = |{}|
    result = Cmd.new("pgrep")
        |> Cmd.args(["-f", "sleep 9999"])
        |> Cmd.exec_output!()

    when result is
        Ok({ stdout_utf8, stderr_utf8_lossy: _ }) ->
            pid_str = stdout_utf8 |> Str.trim |> Str.split_on("\n") |> List.first |> Result.with_default("")
            when Str.to_i64(pid_str) is
                Ok(pid) -> Ok(pid)
                Err(_) -> Err(NotFound)
        Err(_) ->
            Err(NotFound)

## Find helper PID
find_helper_pid! : {} => Result I64 _
find_helper_pid! = |{}|
    result = Cmd.new("pgrep")
        |> Cmd.args(["-f", "pdeathsig-helper"])
        |> Cmd.exec_output!()

    when result is
        Ok({ stdout_utf8, stderr_utf8_lossy: _ }) ->
            pid_str = stdout_utf8 |> Str.trim |> Str.split_on("\n") |> List.first |> Result.with_default("")
            when Str.to_i64(pid_str) is
                Ok(pid) -> Ok(pid)
                Err(_) -> Err(FailedExpectation("Could not parse helper PID"))
        Err(_) ->
            Err(FailedExpectation("Could not find helper process"))

## Check if PID is alive
is_pid_alive! : I64 => Result Bool _
is_pid_alive! = |pid|
    result = Cmd.new("kill")
        |> Cmd.args(["-0", Num.to_str(pid)])
        |> Cmd.exec_output!()

    when result is
        Ok(_) -> Ok(Bool.true)
        Err(_) -> Ok(Bool.false)

## Poll for child to die, with retries
poll_for_child_death! : I64, U64 => Result Bool _
poll_for_child_death! = |pid, max_attempts|
    poll_death_loop!(pid, max_attempts, 0)

poll_death_loop! : I64, U64, U64 => Result Bool _
poll_death_loop! = |pid, max_attempts, attempt|
    if attempt >= max_attempts then
        # Timeout - child is still alive
        Ok(Bool.false)
    else
        alive = is_pid_alive!(pid)?
        if alive then
            Sleep.millis!(100)
            poll_death_loop!(pid, max_attempts, attempt + 1)
        else
            # Child died
            Ok(Bool.true)

## Check if running on Linux
check_platform! : {} => Result {} [NotLinux Str]
check_platform! = |{}|
    result = Cmd.new("uname")
        |> Cmd.args(["-s"])
        |> Cmd.exec_output!()

    when result is
        Ok({ stdout_utf8, stderr_utf8_lossy: _ }) ->
            platform = Str.trim(stdout_utf8)
            if platform == "Linux" then
                Ok({})
            else
                Err(NotLinux(platform))

        Err(_) ->
            # Can't determine platform, assume not Linux
            Err(NotLinux("unknown"))
