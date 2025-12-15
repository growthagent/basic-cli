//! This crate provides common functionality for Roc to interface with `std::process::Command`

use roc_std::{RocList, RocResult, RocStr};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::Mutex;

// Global storage for spawned processes
lazy_static::lazy_static! {
    static ref PROCESSES: Mutex<HashMap<u64, SpawnedProcess>> = Mutex::new(HashMap::new());
    static ref NEXT_PROCESS_ID: Mutex<u64> = Mutex::new(1);
}

struct SpawnedProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[repr(C)]
pub struct Command {
    pub args: RocList<RocStr>,
    pub envs: RocList<RocStr>,
    pub program: RocStr,
    pub clear_envs: bool,
}

impl roc_std::RocRefcounted for Command {
    fn inc(&mut self) {
        self.args.inc();
        self.envs.inc();
        self.program.inc();
    }
    fn dec(&mut self) {
        self.args.dec();
        self.envs.dec();
        self.program.dec();
    }
    fn is_refcounted() -> bool {
        true
    }
}

impl From<&Command> for std::process::Command {
    fn from(roc_cmd: &Command) -> Self {
        let args = roc_cmd.args.into_iter().map(|arg| arg.as_str());
        let num_envs = roc_cmd.envs.len() / 2;
        let flat_envs = &roc_cmd.envs;

        // Environment variables must be passed in key=value pairs
        debug_assert_eq!(flat_envs.len() % 2, 0);

        let mut envs = Vec::with_capacity(num_envs);
        for chunk in flat_envs.chunks(2) {
            let key = chunk[0].as_str();
            let value = chunk[1].as_str();
            envs.push((key, value));
        }

        let mut cmd = std::process::Command::new(roc_cmd.program.as_str());

        // Set arguments
        cmd.args(args);

        // Clear environment variables
        if roc_cmd.clear_envs {
            cmd.env_clear();
        };

        // Set environment variables
        cmd.envs(envs);

        cmd
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[repr(C)]
pub struct OutputFromHostSuccess {
    pub stderr_bytes: roc_std::RocList<u8>,
    pub stdout_bytes: roc_std::RocList<u8>,
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[repr(C)]
pub struct OutputFromHostFailure {
    pub stderr_bytes: roc_std::RocList<u8>,
    pub stdout_bytes: roc_std::RocList<u8>,
    pub exit_code: i32,
}

impl roc_std::RocRefcounted for OutputFromHostSuccess {
    fn inc(&mut self) {
        self.stdout_bytes.inc();
        self.stderr_bytes.inc();
    }
    fn dec(&mut self) {
        self.stdout_bytes.dec();
        self.stderr_bytes.dec();
    }
    fn is_refcounted() -> bool {
        true
    }
}

impl roc_std::RocRefcounted for OutputFromHostFailure {
    fn inc(&mut self) {
        self.exit_code.inc();
        self.stdout_bytes.inc();
        self.stderr_bytes.inc();
    }
    fn dec(&mut self) {
        self.exit_code.dec();
        self.stdout_bytes.dec();
        self.stderr_bytes.dec();
    }
    fn is_refcounted() -> bool {
        true
    }
}

pub fn command_exec_exit_code(roc_cmd: &Command) -> RocResult<i32, roc_io_error::IOErr> {
    match std::process::Command::from(roc_cmd).status() {
        Ok(status) => from_exit_status(status),
        Err(err) => RocResult::err(err.into()),
    }
}

// Status of the child process, successful/exit code/killed by signal
fn from_exit_status(status: std::process::ExitStatus) -> RocResult<i32, roc_io_error::IOErr> {
    match status.code() {
        Some(code) => RocResult::ok(code),
        None => RocResult::err(killed_by_signal_err()),
    }
}

fn killed_by_signal_err() -> roc_io_error::IOErr {
    roc_io_error::IOErr {
        tag: roc_io_error::IOErrTag::Other,
        msg: "Process was killed by operating system signal.".into(),
    }
}

// TODO Can we make this return a tag union (with three variants) ?
pub fn command_exec_output(roc_cmd: &Command) -> RocResult<OutputFromHostSuccess, RocResult<OutputFromHostFailure, roc_io_error::IOErr>> {
    match std::process::Command::from(roc_cmd).output() {
        Ok(output) =>
            match output.status.code() {
                Some(status) => {

                    let stdout_bytes = RocList::from(&output.stdout[..]);
                    let stderr_bytes = RocList::from(&output.stderr[..]);

                    if status == 0 {
                        // Success case
                        RocResult::ok(OutputFromHostSuccess {
                            stderr_bytes,
                            stdout_bytes,
                        })
                    } else {
                        // Failure case
                        RocResult::err(RocResult::ok(OutputFromHostFailure {
                            stderr_bytes,
                            stdout_bytes,
                            exit_code: status,
                        }))
                    }
                },
                None => RocResult::err(RocResult::err(killed_by_signal_err()))
            }
        Err(err) => RocResult::err(RocResult::err(err.into()))
    }
}

/// Spawn a process with piped stdin/stdout/stderr, returns a process ID
pub fn command_spawn_with_pipes(roc_cmd: &Command) -> RocResult<u64, roc_io_error::IOErr> {
    let mut cmd = std::process::Command::from(roc_cmd);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(mut child) => {
            let stdin = child.stdin.take();
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();

            let process_id = {
                let mut next_id = NEXT_PROCESS_ID.lock().unwrap();
                let id = *next_id;
                *next_id += 1;
                id
            };

            {
                let mut processes = PROCESSES.lock().unwrap();
                processes.insert(process_id, SpawnedProcess { child, stdin, stdout, stderr });
            }

            RocResult::ok(process_id)
        }
        Err(err) => RocResult::err(err.into()),
    }
}

/// Write bytes to a spawned process's stdin
pub fn process_write_bytes(process_id: u64, bytes: &RocList<u8>) -> RocResult<(), roc_io_error::IOErr> {
    let mut processes = PROCESSES.lock().unwrap();

    match processes.get_mut(&process_id) {
        Some(process) => {
            match &mut process.stdin {
                Some(stdin) => {
                    match stdin.write_all(bytes.as_slice()) {
                        Ok(()) => {
                            match stdin.flush() {
                                Ok(()) => RocResult::ok(()),
                                Err(err) => RocResult::err(err.into()),
                            }
                        }
                        Err(err) => RocResult::err(err.into()),
                    }
                }
                None => RocResult::err(roc_io_error::IOErr {
                    tag: roc_io_error::IOErrTag::Other,
                    msg: "Process stdin not available".into(),
                }),
            }
        }
        None => RocResult::err(roc_io_error::IOErr {
            tag: roc_io_error::IOErrTag::NotFound,
            msg: "Process not found".into(),
        }),
    }
}

/// Read exactly n bytes from a spawned process's stdout
pub fn process_read_bytes(process_id: u64, num_bytes: u64) -> RocResult<RocList<u8>, roc_io_error::IOErr> {
    let mut processes = PROCESSES.lock().unwrap();

    match processes.get_mut(&process_id) {
        Some(process) => {
            match &mut process.stdout {
                Some(stdout) => {
                    let mut buffer = vec![0u8; num_bytes as usize];
                    match stdout.read_exact(&mut buffer) {
                        Ok(()) => RocResult::ok(RocList::from(&buffer[..])),
                        Err(err) => RocResult::err(err.into()),
                    }
                }
                None => RocResult::err(roc_io_error::IOErr {
                    tag: roc_io_error::IOErrTag::Other,
                    msg: "Process stdout not available".into(),
                }),
            }
        }
        None => RocResult::err(roc_io_error::IOErr {
            tag: roc_io_error::IOErrTag::NotFound,
            msg: "Process not found".into(),
        }),
    }
}

/// Read exactly n bytes from a spawned process's stderr
pub fn process_read_stderr_bytes(process_id: u64, num_bytes: u64) -> RocResult<RocList<u8>, roc_io_error::IOErr> {
    let mut processes = PROCESSES.lock().unwrap();

    match processes.get_mut(&process_id) {
        Some(process) => {
            match &mut process.stderr {
                Some(stderr) => {
                    let mut buffer = vec![0u8; num_bytes as usize];
                    match stderr.read_exact(&mut buffer) {
                        Ok(()) => RocResult::ok(RocList::from(&buffer[..])),
                        Err(err) => RocResult::err(err.into()),
                    }
                }
                None => RocResult::err(roc_io_error::IOErr {
                    tag: roc_io_error::IOErrTag::Other,
                    msg: "Process stderr not available".into(),
                }),
            }
        }
        None => RocResult::err(roc_io_error::IOErr {
            tag: roc_io_error::IOErrTag::NotFound,
            msg: "Process not found".into(),
        }),
    }
}

/// Close a spawned process's stdin (sends EOF to child)
pub fn process_close_stdin(process_id: u64) -> RocResult<(), roc_io_error::IOErr> {
    let mut processes = PROCESSES.lock().unwrap();

    match processes.get_mut(&process_id) {
        Some(process) => {
            process.stdin = None; // Drop the handle, sends EOF to child
            RocResult::ok(())
        }
        None => RocResult::err(roc_io_error::IOErr {
            tag: roc_io_error::IOErrTag::NotFound,
            msg: "Process not found".into(),
        }),
    }
}

/// Kill a spawned process
pub fn process_kill(process_id: u64) -> RocResult<(), roc_io_error::IOErr> {
    let mut processes = PROCESSES.lock().unwrap();

    match processes.remove(&process_id) {
        Some(mut process) => {
            match process.child.kill() {
                Ok(()) => {
                    // Wait to reap the process
                    let _ = process.child.wait();
                    RocResult::ok(())
                }
                Err(err) => RocResult::err(err.into()),
            }
        }
        None => RocResult::err(roc_io_error::IOErr {
            tag: roc_io_error::IOErrTag::NotFound,
            msg: "Process not found".into(),
        }),
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[repr(C)]
pub struct ProcessOutput {
    pub stderr_bytes: roc_std::RocList<u8>,
    pub stdout_bytes: roc_std::RocList<u8>,
    pub exit_code: i32,
}

impl roc_std::RocRefcounted for ProcessOutput {
    fn inc(&mut self) {
        self.stdout_bytes.inc();
        self.stderr_bytes.inc();
    }
    fn dec(&mut self) {
        self.stdout_bytes.dec();
        self.stderr_bytes.dec();
    }
    fn is_refcounted() -> bool {
        true
    }
}

/// Wait for a spawned process to exit and return its output
pub fn process_wait(process_id: u64) -> RocResult<ProcessOutput, roc_io_error::IOErr> {
    let mut processes = PROCESSES.lock().unwrap();

    match processes.remove(&process_id) {
        Some(mut process) => {
            // Read all stdout and stderr before waiting
            let mut stdout_bytes = Vec::new();
            let mut stderr_bytes = Vec::new();

            if let Some(mut stdout) = process.stdout.take() {
                let _ = stdout.read_to_end(&mut stdout_bytes);
            }
            if let Some(mut stderr) = process.stderr.take() {
                let _ = stderr.read_to_end(&mut stderr_bytes);
            }

            match process.child.wait() {
                Ok(status) => {
                    let exit_code = status.code().unwrap_or(-1);
                    RocResult::ok(ProcessOutput {
                        stdout_bytes: RocList::from(&stdout_bytes[..]),
                        stderr_bytes: RocList::from(&stderr_bytes[..]),
                        exit_code,
                    })
                }
                Err(err) => RocResult::err(err.into()),
            }
        }
        None => RocResult::err(roc_io_error::IOErr {
            tag: roc_io_error::IOErrTag::NotFound,
            msg: "Process not found".into(),
        }),
    }
}
