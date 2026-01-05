app [main!] { pf: platform "../platform/main.roc" }

import pf.Stdout
import pf.Cmd
import pf.Arg exposing [Arg]
import pf.Sleep

# Tests all error cases in Cmd functions.

main! : List Arg => Result {} _
main! = |_args|

    # exec!
    expect_err(
        Cmd.exec!("blablaXYZ", []),
        "(Err (FailedToGetExitCode {command: \"{ cmd: blablaXYZ, args:  }\", err: NotFound}))"
    )?

    expect_err(
        Cmd.exec!("cat", ["non_existent.txt"]),
        "(Err (ExecFailed {command: \"cat non_existent.txt\", exit_code: 1}))"
    )?

    # exec_cmd!
    expect_err(
        Cmd.new("blablaXYZ")
        |> Cmd.exec_cmd!,
        "(Err (FailedToGetExitCode {command: \"{ cmd: blablaXYZ, args:  }\", err: NotFound}))"
    )?

    expect_err(
        Cmd.new("cat")
        |> Cmd.arg("non_existent.txt")
        |> Cmd.exec_cmd!,
        "(Err (ExecCmdFailed {command: \"{ cmd: cat, args: non_existent.txt }\", exit_code: 1}))"
    )?

    # exec_output!
    expect_err(
        Cmd.new("blablaXYZ")
        |> Cmd.exec_output!,
        "(Err (FailedToGetExitCode {command: \"{ cmd: blablaXYZ, args:  }\", err: NotFound}))"
    )?

    expect_err(
        Cmd.new("cat")
        |> Cmd.arg("non_existent.txt")
        |> Cmd.exec_output!,
        "(Err (NonZeroExitCode {command: \"{ cmd: cat, args: non_existent.txt }\", exit_code: 1, stderr_utf8_lossy: \"cat: non_existent.txt: No such file or directory\n\", stdout_utf8_lossy: \"\"}))"
    )?

    # Test StdoutContainsInvalidUtf8 - using printf to output invalid UTF-8 bytes
    expect_err(
        Cmd.new("printf")
        |> Cmd.args(["\\377\\376"])  # Invalid UTF-8 sequence
        |> Cmd.exec_output!,
        "(Err (StdoutContainsInvalidUtf8 {cmd_str: \"{ cmd: printf, args: \\377\\376 }\", err: (BadUtf8 {index: 0, problem: InvalidStartByte})}))"
    )?

    # exec_output_bytes!
    expect_err(
        Cmd.new("blablaXYZ")
        |> Cmd.exec_output_bytes!,
        "(Err (FailedToGetExitCodeB NotFound))"
    )?

    expect_err(
        Cmd.new("cat")
        |> Cmd.arg("non_existent.txt")
        |> Cmd.exec_output_bytes!,
        "(Err (NonZeroExitCodeB {exit_code: 1, stderr_bytes: [99, 97, 116, 58, 32, 110, 111, 110, 95, 101, 120, 105, 115, 116, 101, 110, 116, 46, 116, 120, 116, 58, 32, 78, 111, 32, 115, 117, 99, 104, 32, 102, 105, 108, 101, 32, 111, 114, 32, 100, 105, 114, 101, 99, 116, 111, 114, 121, 10], stdout_bytes: []}))"
    )?

    # exec_exit_code!
    expect_err(
        Cmd.new("blablaXYZ")
        |> Cmd.exec_exit_code!,
        "(Err (FailedToGetExitCode {command: \"{ cmd: blablaXYZ, args:  }\", err: NotFound}))"
    )?

    # exec_exit_code! with non-zero exit code is not an error - it returns the exit code
    exit_code = 
        Cmd.new("cat")
        |> Cmd.arg("non_existent.txt")
        |> Cmd.exec_exit_code!()?
    
    if exit_code == 1 then
        Ok({})?
    else
        Err(FailedExpectation(
            """

            - Expected:
            1

            - Got:
            ${Inspect.to_str(exit_code)}

            """
        ))?

    # spawn! basic test
    cat = Cmd.new("cat") |> Cmd.spawn!()?
    cat.write_stdin!([72, 101, 108, 108, 111])?
    output = cat.read_stdout!(5)?
    if output != [72, 101, 108, 108, 111] then
        Err(FailedExpectation(
            """
            spawn read_stdout!:
            - Expected: [72, 101, 108, 108, 111]
            - Got: ${Inspect.to_str(output)}
            """
        ))?
    else
        {}
    cat.kill!({})?

    # close_stdin! test with read_stdout! - cat waits for EOF, then "done" is echoed
    # This REQUIRES close_stdin! to send EOF, otherwise cat blocks forever
    eof_proc = Cmd.new("sh") |> Cmd.args(["-c", "cat; echo done"]) |> Cmd.spawn!()?
    eof_proc.write_stdin!(Str.to_utf8("hi"))?
    eof_proc.close_stdin!({})?
    eof_out = eof_proc.read_stdout!(7)?  # "hi" + "done\n" = 7 bytes
    if eof_out != Str.to_utf8("hidone\n") then
        Err(FailedExpectation(
            """
            close_stdin! EOF test:
            - Expected: ${Inspect.to_str(Str.to_utf8("hidone\n"))}
            - Got: ${Inspect.to_str(eof_out)}
            """
        ))?
    else
        {}
    eof_proc.kill!({})?

    # wait! test
    wait_cat = Cmd.new("cat") |> Cmd.spawn!()?
    wait_cat.write_stdin!(Str.to_utf8("hello"))?
    wait_cat.close_stdin!({})?
    wait_res = wait_cat.wait!({})?
    if wait_res.exit_code != 0 then
        Err(FailedExpectation(
            """
            wait! exit_code:
            - Expected: 0
            - Got: ${Inspect.to_str(wait_res.exit_code)}
            """
        ))?
    else
        {}
    if wait_res.stdout != Str.to_utf8("hello") then
        Err(FailedExpectation(
            """
            wait! stdout:
            - Expected: ${Inspect.to_str(Str.to_utf8("hello"))}
            - Got: ${Inspect.to_str(wait_res.stdout)}
            """
        ))?
    else
        {}

    # wait! with non-zero exit
    exit42 = Cmd.new("sh") |> Cmd.args(["-c", "exit 42"]) |> Cmd.spawn!()?
    exit42_res = exit42.wait!({})?
    if exit42_res.exit_code != 42 then
        Err(FailedExpectation(
            """
            wait! non-zero exit:
            - Expected: 42
            - Got: ${Inspect.to_str(exit42_res.exit_code)}
            """
        ))?
    else
        {}

    # read_stderr! test
    stderr_proc = Cmd.new("sh") |> Cmd.args(["-c", "echo err >&2"]) |> Cmd.spawn!()?
    stderr_proc.close_stdin!({})?
    stderr_out = stderr_proc.read_stderr!(4)?
    if stderr_out != Str.to_utf8("err\n") then
        Err(FailedExpectation(
            """
            read_stderr!:
            - Expected: ${Inspect.to_str(Str.to_utf8("err\n"))}
            - Got: ${Inspect.to_str(stderr_out)}
            """
        ))?
    else
        {}
    stderr_proc.kill!({})?

    # kill! test - verify process is removed after kill
    sleeper = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn!()?
    sleeper.kill!({})?
    # Second kill should fail - process already removed
    when sleeper.kill!({}) is
        Err(KillFailed(_)) -> {}
        other -> Err(FailedExpectation(
            """
            second kill! should fail:
            - Expected: Err(KillFailed(_))
            - Got: ${Inspect.to_str(other)}
            """
        ))?

    # spawn! non-existent
    spawn_result = Cmd.new("nonexistent_xyz") |> Cmd.spawn!()
    when spawn_result is
        Err(SpawnFailed(_)) -> {}
        Ok(_) -> Err(FailedExpectation(
            """
            spawn! non-existent command:
            - Expected: Err(SpawnFailed(_))
            - Got: Ok(ChildProcess)
            """
        ))?
        Err(_) -> Err(FailedExpectation(
            """
            spawn! non-existent command:
            - Expected: Err(SpawnFailed(_))
            - Got: Err (other variant)
            """
        ))?

    # write after close
    closed = Cmd.new("cat") |> Cmd.spawn!()?
    closed.close_stdin!({})?
    when closed.write_stdin!([65]) is
        Err(WriteFailed(_)) -> {}
        other -> Err(FailedExpectation(
            """
            write after close_stdin!:
            - Expected: Err(WriteFailed(_))
            - Got: ${Inspect.to_str(other)}
            """
        ))?
    closed.kill!({})?

    # operations after kill
    killed = Cmd.new("cat") |> Cmd.spawn!()?
    killed.kill!({})?
    when killed.write_stdin!([65]) is
        Err(WriteFailed(_)) -> {}
        other -> Err(FailedExpectation(
            """
            write after kill!:
            - Expected: Err(WriteFailed(_))
            - Got: ${Inspect.to_str(other)}
            """
        ))?
    when killed.read_stdout!(1) is
        Err(ReadFailed(_)) -> {}
        other -> Err(FailedExpectation(
            """
            read after kill!:
            - Expected: Err(ReadFailed(_))
            - Got: ${Inspect.to_str(other)}
            """
        ))?

    # poll! returns Running for running process
    sleeper2 = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn!()?
    poll_res1 = sleeper2.poll!({})?
    when poll_res1 is
        Running -> {}
        Exited(_) ->
            Err(FailedExpectation(
                """
                poll! running process:
                - Expected: Running
                - Got: Exited
                """
            ))?
    sleeper2.kill!({})?

    # poll! multiple times while running - all should return Running
    sleeper3 = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn!()?
    poll_a = sleeper3.poll!({})?
    poll_b = sleeper3.poll!({})?
    poll_c = sleeper3.poll!({})?
    all_running =
        when (poll_a, poll_b, poll_c) is
            (Running, Running, Running) -> Bool.true
            _ -> Bool.false
    if !all_running then
        Err(FailedExpectation(
            """
            poll! multiple times while running:
            - Expected: all Running
            - Got: ${Inspect.to_str([poll_a, poll_b, poll_c])}
            """
        ))?
    else
        {}
    sleeper3.kill!({})?

    # poll! returns correct stdout when process exits
    poll_cat = Cmd.new("sh") |> Cmd.args(["-c", "echo hello"]) |> Cmd.spawn!()?
    poll_cat_loop!(poll_cat, 100)?

    # poll! returns correct stderr when process exits
    poll_stderr = Cmd.new("sh") |> Cmd.args(["-c", "echo err >&2"]) |> Cmd.spawn!()?
    poll_stderr_loop!(poll_stderr, 100)?

    # poll! returns correct non-zero exit code
    poll_exit42 = Cmd.new("sh") |> Cmd.args(["-c", "exit 42"]) |> Cmd.spawn!()?
    poll_exit42_loop!(poll_exit42, 100)?

    # poll! after kill returns NotFound
    sleeper4 = Cmd.new("sleep") |> Cmd.args(["60"]) |> Cmd.spawn!()?
    sleeper4.kill!({})?
    when sleeper4.poll!({}) is
        Err(PollFailed(_)) -> {}
        other -> Err(FailedExpectation(
            """
            poll! after kill!:
            - Expected: Err(PollFailed(_))
            - Got: ${Inspect.to_str(other)}
            """
        ))?

    # poll! after wait! returns NotFound
    wait_first = Cmd.new("sh") |> Cmd.args(["-c", "exit 0"]) |> Cmd.spawn!()?
    _ = wait_first.wait!({})?
    when wait_first.poll!({}) is
        Err(PollFailed(_)) -> {}
        other -> Err(FailedExpectation(
            """
            poll! after wait!:
            - Expected: Err(PollFailed(_))
            - Got: ${Inspect.to_str(other)}
            """
        ))?

    # poll! second time after exited returns NotFound
    poll_once = Cmd.new("sh") |> Cmd.args(["-c", "exit 0"]) |> Cmd.spawn!()?
    poll_once_loop!(poll_once, 100)?
    when poll_once.poll!({}) is
        Err(PollFailed(_)) -> {}
        other -> Err(FailedExpectation(
            """
            poll! second time after exited:
            - Expected: Err(PollFailed(_))
            - Got: ${Inspect.to_str(other)}
            """
        ))?

    Stdout.line!("All tests passed.")?

    Ok({})

expect_err = |err, expected_str|
    if Inspect.to_str(err) == expected_str then
        Ok({})
    else
        Err(FailedExpectation(
            """

            - Expected:
            ${expected_str}

            - Got:
            ${Inspect.to_str(err)}

            """
        ))

## Poll until process exits, verify output matches "hello\n", with max attempts
poll_cat_loop! = |proc, attempts_left|
    if attempts_left == 0 then
        Err(FailedExpectation("poll_cat_loop!: timed out waiting for process"))
    else
        poll_res = proc.poll!({})?
        when poll_res is
            Exited({ exit_code, stdout, stderr: _ }) ->
                # Verify the output
                expected_stdout = Str.to_utf8("hello\n")
                if stdout != expected_stdout then
                    Err(FailedExpectation(
                        """
                        poll! output:
                        - Expected stdout: ${Inspect.to_str(expected_stdout)}
                        - Got: ${Inspect.to_str(stdout)}
                        """
                    ))
                else if exit_code != 0 then
                    Err(FailedExpectation(
                        """
                        poll! exit_code:
                        - Expected: 0
                        - Got: ${Inspect.to_str(exit_code)}
                        """
                    ))
                else
                    Ok({})

            Running ->
                # Not done yet, sleep and try again
                Sleep.millis!(10)
                poll_cat_loop!(proc, attempts_left - 1)

## Poll until process exits (don't check output), with max attempts
poll_once_loop! = |proc, attempts_left|
    if attempts_left == 0 then
        Err(FailedExpectation("poll_once_loop!: timed out waiting for process"))
    else
        poll_res = proc.poll!({})?
        when poll_res is
            Exited(_) -> Ok({})
            Running ->
                Sleep.millis!(10)
                poll_once_loop!(proc, attempts_left - 1)

## Poll until process exits, verify stderr matches "err\n"
poll_stderr_loop! = |proc, attempts_left|
    if attempts_left == 0 then
        Err(FailedExpectation("poll_stderr_loop!: timed out waiting for process"))
    else
        poll_res = proc.poll!({})?
        when poll_res is
            Exited({ exit_code, stdout: _, stderr }) ->
                expected_stderr = Str.to_utf8("err\n")
                if stderr != expected_stderr then
                    Err(FailedExpectation(
                        """
                        poll! stderr:
                        - Expected: ${Inspect.to_str(expected_stderr)}
                        - Got: ${Inspect.to_str(stderr)}
                        """
                    ))
                else if exit_code != 0 then
                    Err(FailedExpectation(
                        """
                        poll! stderr exit_code:
                        - Expected: 0
                        - Got: ${Inspect.to_str(exit_code)}
                        """
                    ))
                else
                    Ok({})

            Running ->
                Sleep.millis!(10)
                poll_stderr_loop!(proc, attempts_left - 1)

## Poll until process exits, verify exit_code is 42
poll_exit42_loop! = |proc, attempts_left|
    if attempts_left == 0 then
        Err(FailedExpectation("poll_exit42_loop!: timed out waiting for process"))
    else
        poll_res = proc.poll!({})?
        when poll_res is
            Exited({ exit_code, stdout: _, stderr: _ }) ->
                if exit_code != 42 then
                    Err(FailedExpectation(
                        """
                        poll! exit_code:
                        - Expected: 42
                        - Got: ${Inspect.to_str(exit_code)}
                        """
                    ))
                else
                    Ok({})

            Running ->
                Sleep.millis!(10)
                poll_exit42_loop!(proc, attempts_left - 1)