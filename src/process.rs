//! Platform process groups: every worker and check runs with its descendants
//! in one group the dispatcher can observe and stop as a unit.
use anyhow::Result;
use std::process::{Child, Command};

pub(crate) use platform::{group_alive, signal_group, spawn_group};

/// How forcefully a group is asked to stop.
#[derive(Clone, Copy)]
pub(crate) enum Stop {
    Terminate,
    Kill,
}

#[cfg(unix)]
mod platform {
    use super::{Child, Command, Result, Stop};
    use anyhow::ensure;
    use nix::{
        errno::Errno,
        sys::signal::{self, Signal},
        unistd::Pid,
    };
    use std::os::unix::process::CommandExt;

    pub(crate) fn spawn_group(cmd: &mut Command) -> Result<Child> {
        Ok(cmd.process_group(0).spawn()?)
    }

    pub(crate) fn group_alive(pid: u32) -> Result<bool> {
        let output = Command::new("ps").args(["-axo", "pgid=,stat="]).output()?;
        ensure!(output.status.success(), "cannot inspect process groups");
        Ok(String::from_utf8_lossy(&output.stdout).lines().any(|row| {
            let mut fields = row.split_whitespace();
            fields.next().and_then(|v| v.parse::<u32>().ok()) == Some(pid)
                && fields.next().is_some_and(|s| !s.starts_with('Z'))
        }))
    }

    pub(crate) fn signal_group(pid: u32, stop: Stop) -> Result<()> {
        let signal = match stop {
            Stop::Terminate => Signal::SIGTERM,
            Stop::Kill => Signal::SIGKILL,
        };
        match signal::killpg(Pid::from_raw(pid as i32), signal) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Windows has no process groups that outlive their leader, so each group is
/// a Job Object. The child starts suspended and is resumed only after it joins
/// the job, so no descendant can escape. Jobs kill their processes when the
/// dispatcher exits, which keeps orphaned workers from blocking a resume.
#[cfg(windows)]
mod platform {
    use super::{Child, Command, Result, Stop};
    use anyhow::{bail, ensure};
    use std::{
        collections::HashMap,
        io, mem,
        os::windows::{io::AsRawHandle, process::CommandExt},
        ptr,
        sync::{Mutex, OnceLock},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, STILL_ACTIVE},
        System::{
            Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent},
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
                QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
            },
            Threading::{
                CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, GetExitCodeProcess, OpenProcess,
                OpenThread, PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread, THREAD_SUSPEND_RESUME,
            },
        },
    };

    struct Job(HANDLE);

    // Job handles are kernel objects usable from any thread.
    unsafe impl Send for Job {}

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn jobs() -> &'static Mutex<HashMap<u32, Job>> {
        static JOBS: OnceLock<Mutex<HashMap<u32, Job>>> = OnceLock::new();
        JOBS.get_or_init(Mutex::default)
    }

    fn check(ok: i32, action: &str) -> Result<()> {
        if ok == 0 {
            bail!("{action}: {}", io::Error::last_os_error());
        }
        Ok(())
    }

    fn create_job() -> Result<Job> {
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        ensure!(
            !handle.is_null(),
            "cannot create job object: {}",
            io::Error::last_os_error()
        );
        let job = Job(handle);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        check(
            unsafe {
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&raw const limits).cast(),
                    mem::size_of_val(&limits) as u32,
                )
            },
            "cannot configure job object",
        )?;
        Ok(job)
    }

    fn resume_threads(pid: u32) -> Result<()> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        ensure!(
            snapshot != INVALID_HANDLE_VALUE,
            "cannot list threads: {}",
            io::Error::last_os_error()
        );
        let snapshot = Job(snapshot);
        let mut entry: THREADENTRY32 = unsafe { mem::zeroed() };
        entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;
        let mut more = unsafe { Thread32First(snapshot.0, &raw mut entry) } != 0;
        while more {
            if entry.th32OwnerProcessID == pid {
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                ensure!(
                    !thread.is_null(),
                    "cannot open worker thread: {}",
                    io::Error::last_os_error()
                );
                let resumed = unsafe { ResumeThread(thread) };
                unsafe { CloseHandle(thread) };
                ensure!(
                    resumed != u32::MAX,
                    "cannot resume worker: {}",
                    io::Error::last_os_error()
                );
            }
            more = unsafe { Thread32Next(snapshot.0, &raw mut entry) } != 0;
        }
        Ok(())
    }

    pub(crate) fn spawn_group(cmd: &mut Command) -> Result<Child> {
        let job = create_job()?;
        let mut child = cmd
            .creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED)
            .spawn()?;
        let joined = check(
            unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle()) },
            "cannot place worker in job object",
        )
        .and_then(|()| resume_threads(child.id()));
        if let Err(error) = joined {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }

        jobs()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(child.id(), job);
        Ok(child)
    }

    fn process_running(pid: u32) -> bool {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut code = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &raw mut code) };
        unsafe { CloseHandle(handle) };
        ok != 0 && code == STILL_ACTIVE as u32
    }

    pub(crate) fn group_alive(pid: u32) -> Result<bool> {
        let mut jobs = jobs()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(job) = jobs.get(&pid) else {
            // A group from an earlier dispatcher: its job closed and killed its
            // processes, so only the leader's PID is left to check.
            return Ok(process_running(pid));
        };
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { mem::zeroed() };
        check(
            unsafe {
                QueryInformationJobObject(
                    job.0,
                    JobObjectBasicAccountingInformation,
                    (&raw mut info).cast(),
                    mem::size_of_val(&info) as u32,
                    ptr::null_mut(),
                )
            },
            "cannot inspect job object",
        )?;
        if info.ActiveProcesses == 0 {
            jobs.remove(&pid);
            return Ok(false);
        }
        Ok(true)
    }

    pub(crate) fn signal_group(pid: u32, stop: Stop) -> Result<()> {
        match stop {
            // Best effort: delivery needs a shared console, and the caller
            // escalates to Kill after a grace period either way.
            Stop::Terminate => {
                unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) };
                Ok(())
            }
            Stop::Kill => {
                let jobs = jobs()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(job) = jobs.get(&pid) {
                    check(
                        unsafe { TerminateJobObject(job.0, 1) },
                        "cannot terminate job object",
                    )?;
                }
                Ok(())
            }
        }
    }
}
