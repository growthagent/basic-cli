app [main!] { pf: platform "../platform/main.roc" }

import pf.Stdout
import pf.Cmd
import pf.Arg exposing [Arg]

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