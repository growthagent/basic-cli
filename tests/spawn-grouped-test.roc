app [main!] { pf: platform "../platform/main.roc" }

import pf.Stdout
import pf.Cmd
import pf.Arg exposing [Arg]
import pf.Sleep
import pf.File

# Tests for spawn_grouped! and kill_grouped!
#
# These tests focus on behavior UNIQUE to spawn_grouped! that differs
# from spawn! (which is tested in cmd-test.roc).
#
# We verify behavior using the API itself (process handles), not external
# tools like ps/grep which are brittle and platform-specific.

main! : List Arg => Result {} _
main! = |_args|

    # === spawn_grouped! basic: spawn, kill, verify dead ===
    proc1 = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn_grouped!()?

    # Verify it's running
    when proc1.poll!({})? is
        Running -> {}
        Exited(_) -> Err(FailedExpectation("proc1 should be Running"))?

    # Kill it
    proc1.kill!({})?

    # Verify it's dead (poll returns error after kill)
    when proc1.poll!({}) is
        Err(PollFailed(_)) -> {}
        other -> Err(FailedExpectation("proc1 poll after kill - expected PollFailed, got ${Inspect.to_str(other)}"))?

    # === kill_grouped! kills all tracked processes ===
    # Spawn 3 processes and KEEP the handles
    proc_a = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn_grouped!()?
    proc_b = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn_grouped!()?
    proc_c = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn_grouped!()?

    # Verify all running
    when proc_a.poll!({})? is
        Running -> {}
        Exited(_) -> Err(FailedExpectation("proc_a should be Running"))?
    when proc_b.poll!({})? is
        Running -> {}
        Exited(_) -> Err(FailedExpectation("proc_b should be Running"))?
    when proc_c.poll!({})? is
        Running -> {}
        Exited(_) -> Err(FailedExpectation("proc_c should be Running"))?

    # Kill ALL grouped processes at once
    Cmd.kill_grouped!({})?

    # Verify ALL are dead via their handles
    when proc_a.poll!({}) is
        Err(PollFailed(_)) -> {}
        other -> Err(FailedExpectation("proc_a after kill_grouped - expected PollFailed, got ${Inspect.to_str(other)}"))?
    when proc_b.poll!({}) is
        Err(PollFailed(_)) -> {}
        other -> Err(FailedExpectation("proc_b after kill_grouped - expected PollFailed, got ${Inspect.to_str(other)}"))?
    when proc_c.poll!({}) is
        Err(PollFailed(_)) -> {}
        other -> Err(FailedExpectation("proc_c after kill_grouped - expected PollFailed, got ${Inspect.to_str(other)}"))?

    # === kill_grouped! twice is safe ===
    Cmd.kill_grouped!({})?  # Should not error even with nothing to kill

    # === kill_grouped! with no processes is safe ===
    # (We just killed everything above, so this tests empty state)
    Cmd.kill_grouped!({})?

    # === Spawn after kill_grouped! works ===
    proc_after = Cmd.new("sh") |> Cmd.args(["-c", "echo ok"]) |> Cmd.spawn_grouped!()?
    result = proc_after.wait!({})?
    if result.stdout != Str.to_utf8("ok\n") then
        Err(FailedExpectation("spawn after kill_grouped failed"))?
    else
        {}

    # === wait! captures stdout, stderr, and exit_code correctly ===
    # Test stdout (already tested above, but let's be explicit)
    proc_stdout = Cmd.new("sh") |> Cmd.args(["-c", "echo hello"]) |> Cmd.spawn_grouped!()?
    stdout_result = proc_stdout.wait!({})?
    if stdout_result.stdout != Str.to_utf8("hello\n") then
        Err(FailedExpectation("wait! stdout mismatch: expected 'hello\\n', got ${Inspect.to_str(stdout_result.stdout)}"))?
    else
        {}

    # Test stderr
    proc_stderr = Cmd.new("sh") |> Cmd.args(["-c", "echo error >&2"]) |> Cmd.spawn_grouped!()?
    stderr_result = proc_stderr.wait!({})?
    if stderr_result.stderr != Str.to_utf8("error\n") then
        Err(FailedExpectation("wait! stderr mismatch: expected 'error\\n', got ${Inspect.to_str(stderr_result.stderr)}"))?
    else
        {}

    # Test exit code
    proc_exit = Cmd.new("sh") |> Cmd.args(["-c", "exit 42"]) |> Cmd.spawn_grouped!()?
    exit_result = proc_exit.wait!({})?
    if exit_result.exit_code != 42 then
        Err(FailedExpectation("wait! exit_code mismatch: expected 42, got ${Num.to_str(exit_result.exit_code)}"))?
    else
        {}

    # === poll! returns Exited with correct data (stdout, stderr, exit_code) ===
    proc_poll = Cmd.new("sh") |> Cmd.args(["-c", "echo polled; echo poll_err >&2; exit 7"]) |> Cmd.spawn_grouped!()?
    # Poll until exited
    poll_exited = poll_until_exited!(proc_poll, 50)?
    when poll_exited is
        { exit_code, stdout, stderr } ->
            if exit_code != 7 then
                Err(FailedExpectation("poll! exit_code mismatch: expected 7, got ${Num.to_str(exit_code)}"))?
            else if stdout != Str.to_utf8("polled\n") then
                Err(FailedExpectation("poll! stdout mismatch: expected 'polled\\n', got ${Inspect.to_str(stdout)}"))?
            else if stderr != Str.to_utf8("poll_err\n") then
                Err(FailedExpectation("poll! stderr mismatch: expected 'poll_err\\n', got ${Inspect.to_str(stderr)}"))?
            else
                {}

    # === wait! with combined stdout AND stderr ===
    proc_both = Cmd.new("sh") |> Cmd.args(["-c", "echo out1; echo err1 >&2; echo out2; echo err2 >&2"]) |> Cmd.spawn_grouped!()?
    both_result = proc_both.wait!({})?
    if both_result.stdout != Str.to_utf8("out1\nout2\n") then
        Err(FailedExpectation("combined stdout mismatch: got ${Inspect.to_str(both_result.stdout)}"))?
    else if both_result.stderr != Str.to_utf8("err1\nerr2\n") then
        Err(FailedExpectation("combined stderr mismatch: got ${Inspect.to_str(both_result.stderr)}"))?
    else
        {}

    # === wait! twice returns error (process already consumed) ===
    proc_wait_twice = Cmd.new("sh") |> Cmd.args(["-c", "echo once"]) |> Cmd.spawn_grouped!()?
    when proc_wait_twice.wait!({}) is
        Ok(_) -> {}  # First call succeeds
        Err(e) -> Err(FailedExpectation("first wait! should succeed, got ${Inspect.to_str(e)}"))?
    when proc_wait_twice.wait!({}) is
        Err(WaitFailed(_)) -> {}
        Ok(_) -> Err(FailedExpectation("wait! twice should fail, but second call succeeded"))?

    # === poll! after wait! returns error ===
    proc_poll_after_wait = Cmd.new("sh") |> Cmd.args(["-c", "echo done"]) |> Cmd.spawn_grouped!()?
    when proc_poll_after_wait.wait!({}) is
        Ok(_) -> {}
        Err(e) -> Err(FailedExpectation("wait! should succeed, got ${Inspect.to_str(e)}"))?
    when proc_poll_after_wait.poll!({}) is
        Err(PollFailed(_)) -> {}
        Ok(_) -> Err(FailedExpectation("poll! after wait! should fail, but succeeded"))?

    # === wait! after kill! returns error ===
    proc_wait_after_kill = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn_grouped!()?
    proc_wait_after_kill.kill!({})?
    when proc_wait_after_kill.wait!({}) is
        Err(WaitFailed(_)) -> {}
        Ok(_) -> Err(FailedExpectation("wait! after kill! should fail, but succeeded"))?

    # === kill! twice on same process returns error ===
    proc_kill_twice = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn_grouped!()?
    when proc_kill_twice.kill!({}) is
        Ok({}) -> {}  # First kill succeeds
        Err(e) -> Err(FailedExpectation("first kill! should succeed, got ${Inspect.to_str(e)}"))?
    when proc_kill_twice.kill!({}) is
        Err(KillFailed(_)) -> {}
        Ok(_) -> Err(FailedExpectation("kill! twice should fail, but second call succeeded"))?

    # === poll! twice after Exited returns error (process consumed) ===
    proc_poll_twice = Cmd.new("sh") |> Cmd.args(["-c", "exit 0"]) |> Cmd.spawn_grouped!()?
    first_poll = poll_until_exited!(proc_poll_twice, 50)?
    when first_poll is
        { exit_code: 0, stdout: _, stderr: _ } -> {}
        other -> Err(FailedExpectation("first poll! should return Exited with exit_code 0, got ${Inspect.to_str(other)}"))?
    # Second poll should fail (process already consumed)
    when proc_poll_twice.poll!({}) is
        Err(PollFailed(_)) -> {}
        Ok(_) -> Err(FailedExpectation("poll! twice should fail, but second call succeeded"))?

    # === CRITICAL: kill_grouped! only kills grouped processes, not spawn! processes ===
    proc_normal = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn!()?
    proc_grouped = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn_grouped!()?

    # Verify both running
    when proc_normal.poll!({})? is
        Running -> {}
        Exited(_) -> Err(FailedExpectation("proc_normal should be Running"))?
    when proc_grouped.poll!({})? is
        Running -> {}
        Exited(_) -> Err(FailedExpectation("proc_grouped should be Running"))?

    # Kill all GROUPED processes
    Cmd.kill_grouped!({})?

    # proc_grouped should be dead
    when proc_grouped.poll!({}) is
        Err(PollFailed(_)) -> {}
        other -> Err(FailedExpectation("proc_grouped after kill_grouped - expected PollFailed, got ${Inspect.to_str(other)}"))?

    # proc_normal should STILL BE RUNNING
    when proc_normal.poll!({})? is
        Running -> {}
        Exited(_) -> Err(FailedExpectation("proc_normal should still be Running after kill_grouped!"))?

    # Clean up the normal process and verify it died
    proc_normal.kill!({})?
    when proc_normal.poll!({}) is
        Err(PollFailed(_)) -> {}
        other -> Err(FailedExpectation("proc_normal after cleanup kill - expected PollFailed, got ${Inspect.to_str(other)}"))?

    # === Individual kill! after kill_grouped! returns error ===
    # (Process was already killed by kill_grouped!)
    proc_d = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn_grouped!()?
    Cmd.kill_grouped!({})?
    when proc_d.kill!({}) is
        Err(KillFailed(_)) -> {}
        other -> Err(FailedExpectation("kill after kill_grouped - expected KillFailed, got ${Inspect.to_str(other)}"))?

    # === stdin/stdout I/O round-trip test ===
    # Verifies that write_stdin!, close_stdin!, and stdout capture work for grouped processes
    proc_cat = Cmd.new("cat") |> Cmd.spawn_grouped!()?
    proc_cat.write_stdin!(Str.to_utf8("hello from stdin"))?
    proc_cat.close_stdin!({})?
    cat_result = proc_cat.wait!({})?
    if cat_result.stdout != Str.to_utf8("hello from stdin") then
        Err(FailedExpectation("stdin/stdout round-trip failed: expected 'hello from stdin', got ${Inspect.to_str(cat_result.stdout)}"))?
    else
        {}

    # === stderr I/O test ===
    # Verifies stderr capture works for grouped processes
    proc_stderr_io = Cmd.new("sh") |> Cmd.args(["-c", "cat >&2"]) |> Cmd.spawn_grouped!()?
    proc_stderr_io.write_stdin!(Str.to_utf8("error output"))?
    proc_stderr_io.close_stdin!({})?
    stderr_io_result = proc_stderr_io.wait!({})?
    if stderr_io_result.stderr != Str.to_utf8("error output") then
        Err(FailedExpectation("stderr I/O test failed: expected 'error output', got ${Inspect.to_str(stderr_io_result.stderr)}"))?
    else
        {}

    # === environment variables work with spawn_grouped! ===
    proc_env = Cmd.new("sh")
        |> Cmd.args(["-c", "echo $MY_TEST_VAR"])
        |> Cmd.env("MY_TEST_VAR", "it_works")
        |> Cmd.spawn_grouped!()?
    env_result = proc_env.wait!({})?
    if env_result.stdout != Str.to_utf8("it_works\n") then
        Err(FailedExpectation("env var test failed: expected 'it_works\\n', got ${Inspect.to_str(env_result.stdout)}"))?
    else
        {}

    # === spawn failure returns error ===
    when Cmd.new("/nonexistent/command/that/does/not/exist") |> Cmd.spawn_grouped!() is
        Err(SpawnFailed(_)) -> {}
        Ok(_) -> Err(FailedExpectation("spawning nonexistent command should fail"))?

    # === read_stdout! basic test ===
    cat_read = Cmd.new("cat") |> Cmd.spawn_grouped!()?
    cat_read.write_stdin!([72, 101, 108, 108, 111])?
    read_out = cat_read.read_stdout!(5)?
    if read_out != [72, 101, 108, 108, 111] then
        Err(FailedExpectation("read_stdout! failed: expected [72, 101, 108, 108, 111], got ${Inspect.to_str(read_out)}"))?
    else
        {}
    cat_read.kill!({})?

    # === close_stdin! + read_stdout! EOF test ===
    eof_proc = Cmd.new("sh") |> Cmd.args(["-c", "cat; echo done"]) |> Cmd.spawn_grouped!()?
    eof_proc.write_stdin!(Str.to_utf8("hi"))?
    eof_proc.close_stdin!({})?
    eof_out = eof_proc.read_stdout!(7)?  # "hi" + "done\n" = 7 bytes
    if eof_out != Str.to_utf8("hidone\n") then
        Err(FailedExpectation("close_stdin! EOF test failed: expected 'hidone\\n', got ${Inspect.to_str(eof_out)}"))?
    else
        {}
    eof_proc.kill!({})?

    # === read_stderr! test ===
    stderr_read = Cmd.new("sh") |> Cmd.args(["-c", "echo err >&2"]) |> Cmd.spawn_grouped!()?
    stderr_read.close_stdin!({})?
    stderr_out = stderr_read.read_stderr!(4)?
    if stderr_out != Str.to_utf8("err\n") then
        Err(FailedExpectation("read_stderr! failed: expected 'err\\n', got ${Inspect.to_str(stderr_out)}"))?
    else
        {}
    stderr_read.kill!({})?

    # === write after close_stdin! returns error ===
    closed = Cmd.new("cat") |> Cmd.spawn_grouped!()?
    closed.close_stdin!({})?
    when closed.write_stdin!([65]) is
        Err(WriteFailed(_)) -> {}
        other -> Err(FailedExpectation("write after close_stdin! should fail, got ${Inspect.to_str(other)}"))?
    closed.kill!({})?

    # === operations after kill! return error ===
    killed = Cmd.new("cat") |> Cmd.spawn_grouped!()?
    killed.kill!({})?
    when killed.write_stdin!([65]) is
        Err(WriteFailed(_)) -> {}
        other -> Err(FailedExpectation("write after kill! should fail, got ${Inspect.to_str(other)}"))?
    when killed.read_stdout!(1) is
        Err(ReadFailed(_)) -> {}
        other -> Err(FailedExpectation("read after kill! should fail, got ${Inspect.to_str(other)}"))?

    # === CRITICAL: Verify process tree killing (grandchildren die) ===
    # This is THE core feature of spawn_grouped! - killing the entire process tree.
    # We spawn a grandchild, write its PID to a temp file, then kill the parent.
    # The grandchild should die because it's in the same process group.

    # Clean up temp file from any previous failed runs (ignore error if doesn't exist)
    _ = File.delete!("/tmp/roc_test_grandchild_pid")

    tree = Cmd.new("sh")
        |> Cmd.args(["-c", "sleep 300 & echo $! > /tmp/roc_test_grandchild_pid; wait"])
        |> Cmd.spawn_grouped!()?
    Sleep.millis!(200)  # Let grandchild spawn and PID be written

    # Read the grandchild PID from the temp file
    read_pid = Cmd.new("cat") |> Cmd.args(["/tmp/roc_test_grandchild_pid"]) |> Cmd.spawn!()?
    read_pid_result = read_pid.wait!({})?
    pid_str = Str.from_utf8(read_pid_result.stdout) |> Result.with_default("") |> Str.trim

    # Verify grandchild is alive before we kill
    alive_check = Cmd.new("sh")
        |> Cmd.args(["-c", "kill -0 ${pid_str} 2>/dev/null"])
        |> Cmd.spawn!()?
    alive_result = alive_check.wait!({})?
    if alive_result.exit_code != 0 then
        Err(FailedExpectation("grandchild PID ${pid_str} should be alive before kill!"))?
    else
        {}

    # Kill the parent (and its process group, including grandchild)
    tree.kill!({})?
    Sleep.millis!(100)  # Let cleanup happen

    # Verify grandchild is dead using kill -0 (returns 0 if process exists, non-zero if dead)
    dead_check = Cmd.new("sh")
        |> Cmd.args(["-c", "kill -0 ${pid_str} 2>/dev/null"])
        |> Cmd.spawn!()?
    dead_result = dead_check.wait!({})?

    # Cleanup temp file
    _ = File.delete!("/tmp/roc_test_grandchild_pid")

    if dead_result.exit_code == 0 then
        Err(FailedExpectation("grandchild PID ${pid_str} still alive after parent killed!"))?
    else
        {}  # exit_code != 0 means process doesn't exist (good!)

    # === Large I/O test ===
    # Verify wait! handles large stdout without deadlock
    # Generate 100KB of output (100 * 1000 bytes + newlines)
    large_proc = Cmd.new("sh") |> Cmd.args(["-c", "dd if=/dev/zero bs=1024 count=100 2>/dev/null | base64"]) |> Cmd.spawn_grouped!()?
    large_result = large_proc.wait!({})?
    large_size = List.len(large_result.stdout)
    # base64 of 100KB is ~137KB (4/3 ratio + newlines)
    if large_size < 100000 then
        Err(FailedExpectation("large I/O test: expected >100KB stdout, got ${Num.to_str(large_size)} bytes"))?
    else
        {}

    # === Simultaneous stdout AND stderr (verify both captured) ===
    # Using 100KB each to verify concurrent reading works (would deadlock with sequential reads)
    both_large = Cmd.new("sh")
        |> Cmd.args(["-c", "dd if=/dev/zero bs=1024 count=100 2>/dev/null | base64; dd if=/dev/zero bs=1024 count=100 2>/dev/null | base64 >&2"])
        |> Cmd.spawn_grouped!()?
    both_large_result = both_large.wait!({})?
    if List.len(both_large_result.stdout) < 100000 then
        Err(FailedExpectation("simultaneous I/O: stdout too small, got ${Num.to_str(List.len(both_large_result.stdout))} bytes"))?
    else if List.len(both_large_result.stderr) < 100000 then
        Err(FailedExpectation("simultaneous I/O: stderr too small, got ${Num.to_str(List.len(both_large_result.stderr))} bytes"))?
    else
        {}

    # NOTE: Cmd.cwd is not available in this version of basic-cli
    # Working directory test skipped

    # === read_stdout! requires exact byte count (fails if not enough data) ===
    # Note: read_stdout! blocks until requested bytes available, fails if stream closes early
    exact_proc = Cmd.new("sh") |> Cmd.args(["-c", "echo -n abc"]) |> Cmd.spawn_grouped!()?
    exact_proc.close_stdin!({})?
    Sleep.millis!(50)  # Let output arrive
    # Request exactly 3 bytes (what's available)
    exact_out = exact_proc.read_stdout!(3)?
    if exact_out != Str.to_utf8("abc") then
        Err(FailedExpectation("exact read test: expected 'abc', got ${Inspect.to_str(exact_out)}"))?
    else
        {}
    exact_proc.kill!({})?

    # Verify that requesting more bytes than available fails
    short_proc = Cmd.new("sh") |> Cmd.args(["-c", "echo -n hi"]) |> Cmd.spawn_grouped!()?
    short_proc.close_stdin!({})?
    Sleep.millis!(50)
    when short_proc.read_stdout!(100) is
        Err(ReadFailed(_)) -> {}  # Expected: not enough data
        Ok(_) -> Err(FailedExpectation("read_stdout! should fail when requesting more bytes than available"))?
    short_proc.kill!({})?

    # === Binary data with null bytes (no corruption) ===
    binary_proc = Cmd.new("sh") |> Cmd.args(["-c", "printf '\\x00\\x01\\x02\\xff'"]) |> Cmd.spawn_grouped!()?
    binary_result = binary_proc.wait!({})?
    if binary_result.stdout != [0, 1, 2, 255] then
        Err(FailedExpectation("binary data test: expected [0, 1, 2, 255], got ${Inspect.to_str(binary_result.stdout)}"))?
    else
        {}

    # === Empty output test ===
    empty_proc = Cmd.new("true") |> Cmd.spawn_grouped!()?
    empty_result = empty_proc.wait!({})?
    if List.len(empty_result.stdout) != 0 then
        Err(FailedExpectation("empty output: expected empty stdout, got ${Num.to_str(List.len(empty_result.stdout))} bytes"))?
    else if List.len(empty_result.stderr) != 0 then
        Err(FailedExpectation("empty output: expected empty stderr, got ${Num.to_str(List.len(empty_result.stderr))} bytes"))?
    else if empty_result.exit_code != 0 then
        Err(FailedExpectation("empty output: expected exit_code 0, got ${Num.to_str(empty_result.exit_code)}"))?
    else
        {}

    # === Rapid spawn/kill (race condition test) ===
    rapid_spawn_kill!(50)?

    # === Stress test: spawn many processes simultaneously ===
    # Spawn 20 processes, verify all can be killed with kill_grouped!
    stress_procs = spawn_many!(20, [])?
    # Verify all running
    verify_all_running!(stress_procs)?
    # Kill all at once
    Cmd.kill_grouped!({})?
    # Verify all dead
    verify_all_dead!(stress_procs)?

    Stdout.line!("All spawn_grouped! tests passed.")

## Poll a process until it exits, with max retries
poll_until_exited! : Cmd.ChildProcess, U64 => Result { exit_code : I32, stdout : List U8, stderr : List U8 } _
poll_until_exited! = |proc, max_retries|
    poll_loop!(proc, max_retries, 0)

poll_loop! : Cmd.ChildProcess, U64, U64 => Result { exit_code : I32, stdout : List U8, stderr : List U8 } _
poll_loop! = |proc, max_retries, attempt|
    if attempt >= max_retries then
        Err(FailedExpectation("Process did not exit after ${Num.to_str(max_retries)} poll attempts"))
    else
        when proc.poll!({}) is
            Ok(Running) ->
                Sleep.millis!(10)
                poll_loop!(proc, max_retries, attempt + 1)

            Ok(Exited(data)) ->
                Ok(data)

            Err(e) ->
                Err(FailedExpectation("poll! failed: ${Inspect.to_str(e)}"))

## Spawn N sleep processes for stress testing
spawn_many! : U64, List Cmd.ChildProcess => Result (List Cmd.ChildProcess) _
spawn_many! = |remaining, acc|
    if remaining == 0 then
        Ok(acc)
    else
        proc = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn_grouped!()?
        spawn_many!(remaining - 1, List.append(acc, proc))

## Verify all processes in list are running
verify_all_running! : List Cmd.ChildProcess => Result {} _
verify_all_running! = |procs|
    when procs is
        [] -> Ok({})
        [proc, .. as rest] ->
            when proc.poll!({}) is
                Ok(Running) -> verify_all_running!(rest)
                Ok(Exited(_)) -> Err(FailedExpectation("stress test: process should be Running"))
                Err(e) -> Err(FailedExpectation("stress test: poll failed ${Inspect.to_str(e)}"))

## Verify all processes in list are dead (poll returns error)
verify_all_dead! : List Cmd.ChildProcess => Result {} _
verify_all_dead! = |procs|
    when procs is
        [] -> Ok({})
        [proc, .. as rest] ->
            when proc.poll!({}) is
                Err(PollFailed(_)) -> verify_all_dead!(rest)
                other -> Err(FailedExpectation("stress test: expected PollFailed, got ${Inspect.to_str(other)}"))

## Rapid spawn/kill to test for race conditions
rapid_spawn_kill! : U64 => Result {} _
rapid_spawn_kill! = |remaining|
    if remaining == 0 then
        Ok({})
    else
        proc = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn_grouped!()?
        proc.kill!({})?
        rapid_spawn_kill!(remaining - 1)
