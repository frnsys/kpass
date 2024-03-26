use std::{
    fmt::{Display, Formatter},
    fs::File,
    path::Path,
};

use anyhow::Result;
use clipboard_ext::{prelude::*, x11_bin::ClipboardContext};
use cocoon::Cocoon;
use inquire::{Password, PasswordDisplayMode, Select};
use keepass::{db::NodeRef, Database, DatabaseKey};

const DB_PATH: &str = "~/docs/pass.kdbx";
const PW_CACHE: &str = "/tmp/.kpw";

/// A KeePass entry.
struct Entry<'a>(&'a keepass::db::Entry);
impl Display for Entry<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let title = self.0.get_title().unwrap_or("(no title)");
        write!(f, "{}", title)
    }
}
impl Entry<'_> {
    fn password(&self) -> Option<&str> {
        self.0.get_password()
    }
}

/// Get the last `n` chars of a string.
fn last_n_chars(s: &str, n: usize) -> &str {
    let idx = s.char_indices().nth_back(n - 1).unwrap().0;
    &s[idx..]
}

/// Try loading the full password from the quick password.
/// There is only one chance to input the correct quick password,
/// otherwise the cached password is destroyed.
fn try_load_pass() -> Result<Option<String>> {
    let pw_path = Path::new(PW_CACHE);
    let pass = if pw_path.exists() {
        let mut file = File::open(pw_path)?;
        let qpw = Password::new("Quick Pass:")
            .with_display_toggle_enabled()
            .with_display_mode(PasswordDisplayMode::Masked)
            .with_formatter(&|_| String::from("🔑"))
            .without_confirmation()
            .prompt()?;

        let cocoon = Cocoon::new(qpw.as_bytes());
        if let Ok(pass) = cocoon.parse(&mut file) {
            let pass = std::str::from_utf8(&pass)?;
            Some(pass.to_string())
        } else {
            println!("! Quick Pass was incorrect.");
            std::fs::remove_file(pw_path)?;
            None
        }
    } else {
        None
    };
    Ok(pass)
}

/// Cache the full password, locked by the quick password;
fn cache_pass(password: &str) -> Result<()> {
    let quick_pw = last_n_chars(password, 3);
    let mut cocoon = Cocoon::new(quick_pw.as_bytes());
    let mut pw_cache = File::create(PW_CACHE)?;
    cocoon
        .dump(password.as_bytes().to_vec(), &mut pw_cache)
        .unwrap();
    Ok(())
}

fn main() -> Result<()> {
    let db_path = shellexpand::tilde(DB_PATH);

    let db = if let Some(pass) = try_load_pass()? {
        let key = DatabaseKey::new().with_password(&pass);
        let mut file = File::open(db_path.as_ref())?;
        Database::open(&mut file, key).expect("Cache password is correct")
    } else {
        loop {
            let pass = Password::new("Password:")
                .with_display_toggle_enabled()
                .with_display_mode(PasswordDisplayMode::Masked)
                .with_formatter(&|_| String::from("🔑"))
                .without_confirmation()
                .prompt()?;

            let key = DatabaseKey::new().with_password(&pass);
            let mut file = File::open(db_path.as_ref())?;
            match Database::open(&mut file, key) {
                Ok(db) => {
                    cache_pass(&pass)?;
                    break db;
                }
                Err(err) => {
                    println!("! Failed to open database. Wrong password?");
                    println!(">   {:?}", err);
                }
            }
        }
    };

    let entries: Vec<_> = db
        .root
        .into_iter()
        .filter_map(|node| match node {
            NodeRef::Group(_) => None,
            NodeRef::Entry(e) => Some(Entry(e)),
        })
        .collect();

    let entry = Select::new("Select entry", entries)
        .with_page_size(15)
        .prompt()?;

    if let Some(pw) = entry.password() {
        let mut ctx = ClipboardContext::new().unwrap();
        ctx.set_contents(pw.into()).unwrap();
        println!("> Copied to clipboard!");
    }

    Ok(())
}
