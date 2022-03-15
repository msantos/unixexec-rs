use std::env;
use std::ffi::CString;
use std::fmt::Write;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::process::exit;

use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::PeerCredentials;
use nix::unistd::{dup2, execvp, getgid, getpid, getuid};

use users::get_user_by_uid;

const PROGNAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

const STDIN_FILENO: i32 = 0;
const STDOUT_FILENO: i32 = 1;

fn usage() -> ! {
    eprintln!(
        r#"{} {}
usage: <SOCKETPATH> <COMMAND> <...>
"#,
        PROGNAME, VERSION,
    );
    exit(1);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.len() < 2 {
        usage()
    }

    let argv: Vec<_> = args[1..]
        .iter()
        .map(|arg| CString::new(arg.as_str()).unwrap())
        .collect();

    unlink(&args[0])?;

    let listener = listen(&args[0])?;
    let result = listener.accept();

    unlink(&args[0])?;

    let (stream, _addr) = result?;
    let fd = stream.into_raw_fd();

    setlocalenv(&args[0])?;
    setremoteenv(fd)?;

    dup2(fd, STDIN_FILENO)?;
    dup2(fd, STDOUT_FILENO)?;

    execvp(&argv[0], &argv)?;

    unreachable!()
}

fn listen(path: &str) -> Result<UnixListener, std::io::Error> {
    UnixListener::bind(path)
}

fn unlink(path: &str) -> std::io::Result<()> {
    match fs::metadata(path) {
        Ok(metadata) => match metadata.file_type().is_socket() {
            true => fs::remove_file(path),
            false => Err(std::io::Error::new(
                ErrorKind::AddrInUse,
                "Socket operation on non-socket",
            )),
        },
        Err(err) => match err.kind() {
            ErrorKind::NotFound => Ok(()),
            _ => Err(err),
        },
    }
}

fn setlocalenv(path: &str) -> Result<(), std::fmt::Error> {
    env::set_var("PROTO", "UNIX");

    let id = getuid();

    let mut pid = String::new();
    let mut uid = String::new();
    let mut gid = String::new();

    write!(&mut pid, "{}", getpid())?;
    write!(&mut uid, "{}", id)?;
    write!(&mut gid, "{}", getgid())?;

    env::set_var("UNIXLOCALPATH", path);
    env::set_var("UNIXLOCALPID", pid);
    env::set_var("UNIXLOCALUID", uid);
    env::set_var("UNIXLOCALGID", gid);

    match get_user_by_uid(id.as_raw()) {
        Some(user) => env::set_var("UNIXLOCALUSER", user.name()),
        None => env::remove_var("UNIXLOCALUSER"),
    }

    Ok(())
}

fn setremoteenv(fd: RawFd) -> Result<(), Box<dyn std::error::Error>> {
    let peer = getsockopt(fd, PeerCredentials)?;

    let mut pid = String::new();
    let mut uid = String::new();
    let mut gid = String::new();

    write!(&mut pid, "{}", peer.pid())?;
    write!(&mut uid, "{}", peer.uid())?;
    write!(&mut gid, "{}", peer.gid())?;

    env::set_var("UNIXREMOTEPID", pid);
    env::set_var("UNIXREMOTEEUID", uid);
    env::set_var("UNIXREMOTEEGID", gid);

    match get_user_by_uid(peer.uid()) {
        Some(user) => env::set_var("UNIXREMOTEUSER", user.name()),
        None => env::remove_var("UNIXREMOTEUSER"),
    }

    Ok(())
}
