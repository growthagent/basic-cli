//! This crate provides common functionality for Roc to interface with `std::process::Command`

use command_group::{CommandGroup, GroupChild};
use roc_std::{RocList, RocRefcounted, RocResult, RocStr};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;

/// Lock a mutex, recovering if it was poisoned by a panic in another thread.
fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Read stdout and stderr concurrently to avoid deadlock when both pipes have large data.
///
/// Without concurrent reading, if both pipes fill their buffers (~64KB each), the child
/// blocks writing and the parent blocks reading, causing deadlock.
///
/// Returns individual results for each pipe so callers can handle partial success.
fn read_pipes_concurrently(
    stdout: Option<ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
) -> (std::io::Result<Vec<u8>>, std::io::Result<Vec<u8>>) {
    let stdout_handle = stdout.map(|mut pipe| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).map(|_| bytes)
        })
    });

    let stderr_handle = stderr.map(|mut pipe| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).map(|_| bytes)
        })
    });

    let stdout_result = stdout_handle
        .map(|h| h.join().unwrap_or_else(|_| Ok(Vec::new())))
        .unwrap_or_else(|| Ok(Vec::new()));
    let stderr_result = stderr_handle
        .map(|h| h.join().unwrap_or_else(|_| Ok(Vec::new())))
        .unwrap_or_else(|| Ok(Vec::new()));

    (stdout_result, stderr_result)
}

// =============================================================================
// Trait and helpers to reduce duplication between spawn! and spawn_grouped!
// =============================================================================

/// Trait abstracting over Child and GroupChild for common operations.
trait ChildLike {
    fn kill(&mut self) -> std::io::Result<()>;
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus>;
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl ChildLike for Child {
    fn kill(&mut self) -> std::io::Result<()> { Child::kill(self) }
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> { Child::wait(self) }
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> { Child::try_wait(self) }
}

impl ChildLike for GroupChild {
    fn kill(&mut self) -> std::io::Result<()> { GroupChild::kill(self) }
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> { GroupChild::wait(self) }
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> { GroupChild::try_wait(self) }
}

/// Generic process struct used by both spawn! and spawn_grouped!
struct Process<C> {
    child: C,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
}

/// Write bytes to a process's stdin
fn write_to_stdin(stdin: &mut Option<ChildStdin>, bytes: &[u8]) -> RocResult<(), roc_io_error::IOErr> {
    match stdin {
        Some(ref mut handle) => {
            match handle.write_all(bytes) {
                Ok(()) => match handle.flush() {
                    Ok(()) => RocResult::ok(()),
                    Err(err) => RocResult::err(err.into()),
                },
                Err(err) => RocResult::err(err.into()),
            }
        }
        None => RocResult::err(roc_io_error::IOErr {
            tag: roc_io_error::IOErrTag::Other,
            msg: "Process stdin not available".into(),
        }),
    }
}

/// Read exactly n bytes from stdout
fn read_from_stdout(stdout: &mut Option<ChildStdout>, num_bytes: u64) -> RocResult<RocList<u8>, roc_io_error::IOErr> {
    match stdout {
        Some(ref mut handle) => {
            let mut buffer = vec![0u8; num_bytes as usize];
            match handle.read_exact(&mut buffer) {
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

/// Read exactly n bytes from stderr
fn read_from_stderr(stderr: &mut Option<std::process::ChildStderr>, num_bytes: u64) -> RocResult<RocList<u8>, roc_io_error::IOErr> {
    match stderr {
        Some(ref mut handle) => {
            let mut buffer = vec![0u8; num_bytes as usize];
            match handle.read_exact(&mut buffer) {
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

/// Kill a process and reap it
fn kill_process<C: ChildLike>(process: &mut Process<C>) -> RocResult<(), roc_io_error::IOErr> {
    match process.child.kill() {
        Ok(()) => {
            let _ = process.child.wait();
            RocResult::ok(())
        }
        Err(err) => RocResult::err(err.into()),
    }
}

/// Wait for a process to exit and return its output
fn wait_for_process<C: ChildLike>(process: &mut Process<C>) -> RocResult<ProcessOutput, roc_io_error::IOErr> {
    let (stdout_result, stderr_result) = read_pipes_concurrently(
        process.stdout.take(),
        process.stderr.take(),
    );

    // Propagate pipe read errors
    let stdout_bytes = match stdout_result {
        Ok(bytes) => bytes,
        Err(err) => return RocResult::err(err.into()),
    };
    let stderr_bytes = match stderr_result {
        Ok(bytes) => bytes,
        Err(err) => return RocResult::err(err.into()),
    };

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

/// Poll a process for exit status
fn poll_process<C: ChildLike>(process: &mut Process<C>) -> Result<Option<ProcessOutput>, std::io::Error> {
    match process.child.try_wait()? {
        Some(status) => {
            let (stdout_result, stderr_result) = read_pipes_concurrently(
                process.stdout.take(),
                process.stderr.take(),
            );
            let stdout_bytes = stdout_result?;
            let stderr_bytes = stderr_result?;
            let exit_code = status.code().unwrap_or(-1);
            Ok(Some(ProcessOutput {
                stdout_bytes: RocList::from(&stdout_bytes[..]),
                stderr_bytes: RocList::from(&stderr_bytes[..]),
                exit_code,
            }))
        }
        None => Ok(None),
    }
}

fn not_found_error(msg: &str) -> roc_io_error::IOErr {
    roc_io_error::IOErr {
        tag: roc_io_error::IOErrTag::NotFound,
        msg: msg.into(),
    }
}

// Type aliases for clarity
type SpawnedProcess = Process<Child>;
type GroupedProcess = Process<GroupChild>;

// Global storage for spawned processes (regular spawn!)
lazy_static::lazy_static! {
    static ref PROCESSES: Mutex<HashMap<u64, SpawnedProcess>> = Mutex::new(HashMap::new());
    static ref NEXT_PROCESS_ID: Mutex<u64> = Mutex::new(1);
}

// Global storage for grouped processes (spawn_grouped! - cleaned up on exit)
// Uses process groups on Unix and Job Objects on Windows to ensure the
// entire process tree is killed when the parent dies.
lazy_static::lazy_static! {
    static ref GROUPED_PROCESSES: Mutex<HashMap<u64, GroupedProcess>> = Mutex::new(HashMap::new());
    static ref NEXT_GROUPED_ID: Mutex<u64> = Mutex::new(1);
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
            let process_id = {
                let mut next_id = lock_or_recover(&NEXT_PROCESS_ID);
                let id = *next_id;
                *next_id += 1;
                id
            };

            let process = Process {
                stdin: child.stdin.take(),
                stdout: child.stdout.take(),
                stderr: child.stderr.take(),
                child,
            };

            lock_or_recover(&PROCESSES).insert(process_id, process);
            RocResult::ok(process_id)
        }
        Err(err) => RocResult::err(err.into()),
    }
}

/// Write bytes to a spawned process's stdin
pub fn process_write_bytes(process_id: u64, bytes: &RocList<u8>) -> RocResult<(), roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&PROCESSES);
    match processes.get_mut(&process_id) {
        Some(process) => write_to_stdin(&mut process.stdin, bytes.as_slice()),
        None => RocResult::err(not_found_error("Process not found")),
    }
}

/// Read exactly n bytes from a spawned process's stdout
pub fn process_read_bytes(process_id: u64, num_bytes: u64) -> RocResult<RocList<u8>, roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&PROCESSES);
    match processes.get_mut(&process_id) {
        Some(process) => read_from_stdout(&mut process.stdout, num_bytes),
        None => RocResult::err(not_found_error("Process not found")),
    }
}

/// Read exactly n bytes from a spawned process's stderr
pub fn process_read_stderr_bytes(process_id: u64, num_bytes: u64) -> RocResult<RocList<u8>, roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&PROCESSES);
    match processes.get_mut(&process_id) {
        Some(process) => read_from_stderr(&mut process.stderr, num_bytes),
        None => RocResult::err(not_found_error("Process not found")),
    }
}

/// Close a spawned process's stdin (sends EOF to child)
pub fn process_close_stdin(process_id: u64) -> RocResult<(), roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&PROCESSES);
    match processes.get_mut(&process_id) {
        Some(process) => {
            process.stdin = None;
            RocResult::ok(())
        }
        None => RocResult::err(not_found_error("Process not found")),
    }
}

/// Kill a spawned process
pub fn process_kill(process_id: u64) -> RocResult<(), roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&PROCESSES);
    match processes.remove(&process_id) {
        Some(mut process) => kill_process(&mut process),
        None => RocResult::err(not_found_error("Process not found")),
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
    let mut processes = lock_or_recover(&PROCESSES);
    match processes.remove(&process_id) {
        Some(mut process) => wait_for_process(&mut process),
        None => RocResult::err(not_found_error("Process not found")),
    }
}

// === PollResult: Tag union [Exited { exit_code: I32, stderr: List U8, stdout: List U8 }, Running] ===
// Discriminants assigned alphabetically: Exited=0, Running=1

/// Discriminant for PollResult tag union.
/// Roc assigns discriminants alphabetically: Exited=0, Running=1
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[repr(u8)]
pub enum PollResultDiscriminant {
    Exited = 0,
    Running = 1,
}

roc_std::roc_refcounted_noop_impl!(PollResultDiscriminant);

/// Payload for the Exited variant.
/// Fields are ordered by size (largest first), then alphabetically:
/// - stderr_bytes: 24 bytes (List)
/// - stdout_bytes: 24 bytes (List)
/// - exit_code: 4 bytes (I32) + 4 padding
#[derive(Clone, Debug)]
#[repr(C)]
pub struct PollResultExited {
    pub stderr_bytes: roc_std::RocList<u8>,
    pub stdout_bytes: roc_std::RocList<u8>,
    pub exit_code: i32,
}

/// Union of all PollResult payloads.
/// Exited has a record payload, Running has no payload (unit).
#[repr(C, align(8))]
pub union PollResultPayload {
    pub Exited: core::mem::ManuallyDrop<PollResultExited>,
    pub Running: (),
}

/// Tag union: [Exited { exit_code: I32, stderr: List U8, stdout: List U8 }, Running]
#[repr(C)]
pub struct PollResult {
    pub payload: PollResultPayload,
    pub discriminant: PollResultDiscriminant,
}

impl PollResult {
    pub fn Exited(exit_code: i32, stdout_bytes: RocList<u8>, stderr_bytes: RocList<u8>) -> Self {
        Self {
            discriminant: PollResultDiscriminant::Exited,
            payload: PollResultPayload {
                Exited: core::mem::ManuallyDrop::new(PollResultExited {
                    stderr_bytes,
                    stdout_bytes,
                    exit_code,
                }),
            },
        }
    }

    pub fn Running() -> Self {
        Self {
            discriminant: PollResultDiscriminant::Running,
            payload: PollResultPayload { Running: () },
        }
    }
}

impl Drop for PollResult {
    fn drop(&mut self) {
        match self.discriminant {
            PollResultDiscriminant::Exited => unsafe {
                core::mem::ManuallyDrop::drop(&mut self.payload.Exited)
            },
            PollResultDiscriminant::Running => {}
        }
    }
}

impl roc_std::RocRefcounted for PollResult {
    fn inc(&mut self) {
        match self.discriminant {
            PollResultDiscriminant::Exited => unsafe {
                (*self.payload.Exited).stderr_bytes.inc();
                (*self.payload.Exited).stdout_bytes.inc();
            },
            PollResultDiscriminant::Running => {}
        }
    }
    fn dec(&mut self) {
        match self.discriminant {
            PollResultDiscriminant::Exited => unsafe {
                (*self.payload.Exited).stderr_bytes.dec();
                (*self.payload.Exited).stdout_bytes.dec();
            },
            PollResultDiscriminant::Running => {}
        }
    }
    fn is_refcounted() -> bool {
        true
    }
}

// Compile-time size assertions for FFI compatibility
const _: () = {
    assert!(core::mem::size_of::<PollResultExited>() == 56);
    assert!(core::mem::size_of::<PollResultPayload>() == 56);
    assert!(core::mem::size_of::<PollResult>() == 64);
    assert!(core::mem::align_of::<PollResult>() == 8);

    // Verify field offsets in PollResultExited
    assert!(core::mem::offset_of!(PollResultExited, stderr_bytes) == 0);
    assert!(core::mem::offset_of!(PollResultExited, stdout_bytes) == 24);
    assert!(core::mem::offset_of!(PollResultExited, exit_code) == 48);

    // Verify PollResult layout: payload at 0, discriminant at 56
    assert!(core::mem::offset_of!(PollResult, payload) == 0);
    assert!(core::mem::offset_of!(PollResult, discriminant) == 56);
};

/// Check if a spawned process has exited without blocking.
/// Returns `Running` if the process is still running, or `Exited { ... }` with
/// the exit code and output if the process has finished.
///
/// When returning `Exited`, the process is removed from the map and subsequent
/// calls will return `NotFound`. The stdout/stderr are read in full.
///
/// Note: Read errors on stdout/stderr are silently ignored (returns empty bytes).
/// This matches `process_wait` behavior and is safe because read errors on pipes
/// from exited processes are extremely rare (data is kernel-buffered).
pub fn process_poll(process_id: u64) -> RocResult<PollResult, roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&PROCESSES);

    match processes.get_mut(&process_id) {
        Some(process) => match poll_process(process) {
            Ok(Some(output)) => {
                processes.remove(&process_id);
                RocResult::ok(PollResult::Exited(output.exit_code, output.stdout_bytes, output.stderr_bytes))
            }
            Ok(None) => RocResult::ok(PollResult::Running()),
            Err(err) => RocResult::err(err.into()),
        },
        None => RocResult::err(not_found_error("Process not found")),
    }
}

// =============================================================================
// spawn_grouped! - Processes that are automatically cleaned up when parent exits
// =============================================================================

/// Spawn a process in a managed group that dies with the parent.
///
/// Platform behavior:
/// - **Linux**: Uses PR_SET_PDEATHSIG so child receives SIGKILL when parent dies.
///   100% reliable even for SIGKILL of parent.
/// - **macOS**: Uses process groups. Handles normal exit, SIGINT, SIGTERM, crashes.
///   Children may survive if parent is killed with SIGKILL (macOS kernel limitation).
/// - **Windows**: Uses Job Objects (via command-group) to automatically kill
///   all children when the parent exits. 100% reliable.
pub fn command_spawn_grouped(roc_cmd: &Command) -> RocResult<u64, roc_io_error::IOErr> {
    let mut cmd = std::process::Command::from(roc_cmd);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // On Linux, set PR_SET_PDEATHSIG so child dies when parent dies (even SIGKILL)
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                let ret = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                if ret == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    match cmd.group_spawn() {
        Ok(mut child) => {
            let process_id = {
                let mut next_id = lock_or_recover(&NEXT_GROUPED_ID);
                let id = *next_id;
                *next_id += 1;
                id
            };

            let process = Process {
                stdin: child.inner().stdin.take(),
                stdout: child.inner().stdout.take(),
                stderr: child.inner().stderr.take(),
                child,
            };

            lock_or_recover(&GROUPED_PROCESSES).insert(process_id, process);
            RocResult::ok(process_id)
        }
        Err(err) => RocResult::err(err.into()),
    }
}

/// Kill all grouped processes. Called automatically on exit.
pub fn process_kill_all_grouped() -> RocResult<(), roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&GROUPED_PROCESSES);
    for (_, mut process) in processes.drain() {
        let _ = kill_process(&mut process);
    }
    RocResult::ok(())
}

/// Kill a specific grouped process by ID
pub fn grouped_process_kill(process_id: u64) -> RocResult<(), roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&GROUPED_PROCESSES);
    match processes.remove(&process_id) {
        Some(mut process) => kill_process(&mut process),
        None => RocResult::err(not_found_error("Grouped process not found")),
    }
}

/// Poll a grouped process for exit status
pub fn grouped_process_poll(process_id: u64) -> RocResult<PollResult, roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&GROUPED_PROCESSES);

    match processes.get_mut(&process_id) {
        Some(process) => match poll_process(process) {
            Ok(Some(output)) => {
                processes.remove(&process_id);
                RocResult::ok(PollResult::Exited(output.exit_code, output.stdout_bytes, output.stderr_bytes))
            }
            Ok(None) => RocResult::ok(PollResult::Running()),
            Err(err) => RocResult::err(err.into()),
        },
        None => RocResult::err(not_found_error("Grouped process not found")),
    }
}

/// Wait for a grouped process to exit
pub fn grouped_process_wait(process_id: u64) -> RocResult<ProcessOutput, roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&GROUPED_PROCESSES);
    match processes.remove(&process_id) {
        Some(mut process) => wait_for_process(&mut process),
        None => RocResult::err(not_found_error("Grouped process not found")),
    }
}

/// Write bytes to a grouped process's stdin
pub fn grouped_process_write_bytes(process_id: u64, bytes: &RocList<u8>) -> RocResult<(), roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&GROUPED_PROCESSES);
    match processes.get_mut(&process_id) {
        Some(process) => write_to_stdin(&mut process.stdin, bytes.as_slice()),
        None => RocResult::err(not_found_error("Grouped process not found")),
    }
}

/// Read exactly n bytes from a grouped process's stdout
pub fn grouped_process_read_bytes(process_id: u64, num_bytes: u64) -> RocResult<RocList<u8>, roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&GROUPED_PROCESSES);
    match processes.get_mut(&process_id) {
        Some(process) => read_from_stdout(&mut process.stdout, num_bytes),
        None => RocResult::err(not_found_error("Grouped process not found")),
    }
}

/// Read exactly n bytes from a grouped process's stderr
pub fn grouped_process_read_stderr_bytes(process_id: u64, num_bytes: u64) -> RocResult<RocList<u8>, roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&GROUPED_PROCESSES);
    match processes.get_mut(&process_id) {
        Some(process) => read_from_stderr(&mut process.stderr, num_bytes),
        None => RocResult::err(not_found_error("Grouped process not found")),
    }
}

/// Close a grouped process's stdin (sends EOF to child)
pub fn grouped_process_close_stdin(process_id: u64) -> RocResult<(), roc_io_error::IOErr> {
    let mut processes = lock_or_recover(&GROUPED_PROCESSES);
    match processes.get_mut(&process_id) {
        Some(process) => {
            process.stdin = None;
            RocResult::ok(())
        }
        None => RocResult::err(not_found_error("Grouped process not found")),
    }
}
