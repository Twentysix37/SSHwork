#![allow(dead_code, unreachable_code, unused_imports, unused_variables, unused_assignments)]

use std::fs::{read_dir, read_to_string as read_file, remove_file, DirEntry}; // Filesystem utils.
use std::path::Path; // Path to entry in filesystem.
use std::process::Command; // Child process runner.

const SSH_DIR: &str = "~/.ssh";

type Error = String;
type IsInstalled = bool;

fn get_ssh_info() -> Result<IsInstalled, Error> {
    let mut ssh_installed = false;
    
    // Check that each client-side SSH binary is installed; forward any I/O errors.
    todo!("refactor the following into a `for`-loop and run for each client-side binary: `ssh`, `ssh-keygen`, `ssh-agent`, `ssh-add`");
    let bin = "ssh";
    let child_output = Command::new("which").arg(bin).output().map_err(|err| {
        format!("failed to run process: `which {bin}`, error: `{err}`")
    })?;
    if child_output.status.success() {
        let child_stdout = String::from_utf8(child_output.stdout)
            .map_err(|err| format!("failed to parse process stdout: `which {bin}`, error: `{err}`"))?;
        let bin_path = child_stdout.trim();
        println!("[✓] {bin}: found ({bin_path})");
        ssh_installed = true;
    } else {
        println!("[✗] {bin}: NOT FOUND");
    };

    todo!("if SSH is installed, print SSH (i.e. OpenSSH) version using `ssh -V`");    
    todo!("print whether or not SSH directory `~/.ssh/` exists using `Path::{{new, is_dir, exists}}`");
    todo!("if SSH dir exists, print whether or not SSH config file `~/.ssh/config` exists");    
    
    Ok(ssh_installed)
}

// `std::fs::read_dir` has an ugly API, so I added this wrapper; returns an error if retrieving
// filesystem info for `dir_path` directory or any of the directory's entries fails.
fn read_ssh_dir() -> Result<Vec<DirEntry>, Error> {
    read_dir(SSH_DIR)
        .map_err(|err| format!("failed to read dir: `{SSH_DIR}`, error: `{err}`"))?
        .collect::<std::io::Result<Vec<DirEntry>>>()
        .map_err(|err| format!("failed to get fs info for entry in dir: `{SSH_DIR}`, error: `{err}`"))
}

// List SSH keypairs in `~/.ssh/`; return any I/O errors.
fn list_keypairs() -> Result<(), Error> {
    let ssh_dir: Vec<DirEntry> = read_ssh_dir()?;
    
    let key_names: Vec<String> = todo!(
        "filter ssh directory's entries for any pairs of files matching ssh's keypair file \
        name pattern: `<key name>.pub` and `<key name>`"
    );

    for key_name in key_names {
        let keys_are_valid = todo!("check if each key file is a valid ssh key using: `ssh-keygen -l -f <path to key>`");
        todo!("if each keypair key is valid, then print the keypair's name");
    }
    
    Ok(())
}

// Generate RSA 4096-bit SSH keypair `~/.ssh/<key name>` (private key) and `~/.ssh/<key name>.pub` (public key); return an error if keygen fails.
fn gen_rsa_keypair(name: &str, password: Option<&str>, comment: Option<&str>) -> Result<(), Error> {
    todo!("generate RSA 4096-bit ssh keypair using `ssh -t rsa -b 4096 ...`");
}

// Generate Ed25519 SSH keypair `~/.ssh/<key name>` (private key) and `~/.ssh/<key name>.pub` (public key); return an error if keygen fails.
fn gen_ed_keypair(name: &str, password: Option<&str>, comment: Option<&str>) -> Result<(), Error> {
    todo!("generate Ed25519 ssh keypair using `ssh -t ed25519 ...`");
}

// Print public key file found in `~/.ssh/`; forward any I/O errors.
fn show_pubkey(name: &str) -> Result<(), Error> {
    todo!("use `read_file` to print key file's contents");
}

// Delete SSH keypair files from `~/.ssh/`; forward any I/O errors.
fn delete_keypair(name: &str) -> Result<(), Error> {
    todo!("use `remove_file` to remove ssh keypair files");
}

fn main() -> Result<(), Error> {
    let ssh_installed = get_ssh_info()?;
    if !ssh_installed {
        return Ok(());
    }
    
    list_keypairs()?;
        
    // Generate two SSH keypairs; one RSA and one Ed25519.
    let rsa_key_name = todo!("rsa key name");
    let ed_key_name = todo!("ed key name");
    let key_password: Option<&str> = todo!("either `Some(password)` or `None`");
    let key_comment: Option<&str> = todo!("either `Some(my_name_email_keyname_etc)` or `None`");
    gen_rsa_keypair(rsa_key_name, key_password, key_comment)?;
    gen_ed_keypair(ed_key_name, key_password, key_comment)?;
    
    // Check that new keypairs were created.
    list_keypairs()?;
    
    // Print public keys.
    show_pubkey(rsa_key_name)?;
    show_pubkey(ed_key_name)?;
        
    // Delete generated keypairs.
    delete_keypair(rsa_key_name)?;
    delete_keypair(ed_key_name)?;
}