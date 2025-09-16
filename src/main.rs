use std::{
    env,
    fmt::{Display, Formatter},
    fs::File,
    path::Path,
    process::exit,
};

use anyhow::Result;
use cocoon::Cocoon;
use inquire::{Confirm, Editor, Password, PasswordDisplayMode, Select, Text, required};
use keepass::{
    Database, DatabaseKey,
    db::{Entry as KEntry, Group, Node, NodeRef, Value},
};
use passwords::PasswordGenerator;
use wl_clipboard_rs::copy::{MimeType, Options, Source};

const PW_CACHE: &str = "/tmp/.kpw";

/// A KeePass entry.
struct Entry<'a>(&'a KEntry);
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

    fn username(&self) -> Option<&str> {
        self.0.get_username()
    }

    fn url(&self) -> Option<&str> {
        self.0.get_url()
    }

    fn notes(&self) -> Option<&str> {
        self.0.fields.get("Notes").and_then(|val| match val {
            Value::Unprotected(notes) => Some(notes.as_str()),
            Value::Protected(data) => std::str::from_utf8(data.unsecure()).ok(),
            _ => None,
        })
    }
}

/// For conveniently editing an entry.
struct EditEntry<'a>(&'a mut KEntry);
impl EditEntry<'_> {
    fn set_title(&mut self) -> Result<()> {
        let current = self.0.get_title().unwrap_or("");
        let value = Text::new("Title: ")
            .with_initial_value(current)
            .with_validator(required!())
            .prompt()?;
        self.0
            .fields
            .insert("Title".to_string(), Value::Unprotected(value));
        Ok(())
    }

    fn set_username(&mut self) -> Result<()> {
        let current = self.0.get_username().unwrap_or("");
        let value = Text::new("UserName: ")
            .with_initial_value(current)
            .with_validator(required!())
            .prompt()?;
        self.0
            .fields
            .insert("UserName".to_string(), Value::Unprotected(value));
        Ok(())
    }

    fn set_notes(&mut self) -> Result<()> {
        let entry = Entry(self.0);
        let current = entry.notes().unwrap_or("");
        let notes = Editor::new("Notes: ")
            .with_predefined_text(current)
            .prompt()?;
        self.0.fields.insert(
            "Notes".to_string(),
            Value::Protected(notes.as_bytes().into()),
        );
        Ok(())
    }

    fn set_manual_password(&mut self) -> Result<()> {
        let entry = Entry(self.0);
        let current = entry.password().unwrap_or("");
        let password = Text::new("Password: ")
            .with_initial_value(current)
            .with_validator(required!())
            .prompt()?;
        self.0.fields.insert(
            "Password".to_string(),
            Value::Protected(password.as_bytes().into()),
        );
        Ok(())
    }

    fn set_random_password(&mut self) -> Result<()> {
        let pg = PasswordGenerator {
            length: 12,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: true,
            spaces: false,
            exclude_similar_characters: false,
            strict: true,
        };
        let password = pg.generate_one().unwrap();
        println!("> Password generated.");
        self.0.fields.insert(
            "Password".to_string(),
            Value::Protected(password.as_bytes().into()),
        );
        Ok(())
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
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        println!("Please provide an database path.");
        exit(1);
    }

    let db_path = Path::new(&args[0]);

    let (mut db, key) = if let Some(pass) = try_load_pass()? {
        let key = DatabaseKey::new().with_password(&pass);
        let mut file = File::open(db_path)?;
        let db = Database::open(&mut file, key.clone()).expect("Cache password is correct");
        (db, key)
    } else {
        loop {
            let pass = Password::new("Password:")
                .with_display_toggle_enabled()
                .with_display_mode(PasswordDisplayMode::Masked)
                .with_formatter(&|_| String::from("🔑"))
                .without_confirmation()
                .prompt()?;

            let key = DatabaseKey::new().with_password(&pass);
            let mut file = File::open(db_path)?;
            match Database::open(&mut file, key.clone()) {
                Ok(db) => {
                    cache_pass(&pass)?;
                    break (db, key);
                }
                Err(err) => {
                    println!("! Failed to open database. Wrong password?");
                    println!(">   {:?}", err);
                }
            }
        }
    };

    loop {
        let action = Select::new(">", vec!["Search", "Edit", "New", "Quit"]).prompt()?;
        match action {
            "Quit" => {
                break;
            }
            "Search" => {
                let entry = pick_entry(&db)?;
                view_entry(&entry)?
            }
            "New" => {
                let entry = new_entry()?;

                view_entry(&Entry(&entry))?;
                let confirm = Confirm::new("Ok?").with_default(true).prompt()?;

                if confirm {
                    println!("> Saving...");
                    db.root.add_child(entry);
                    save_db(&db, key.clone(), db_path)?;
                    println!("> Saved.");
                }
            }
            "Edit" => {
                let entry = pick_entry(&db)?;
                view_entry(&entry)?;

                let uuid = entry.0.get_uuid().as_u128();
                let entry =
                    get_entry_mut(&mut db, uuid).expect("We just checked that the entry exists");

                edit_entry(entry)?;
                save_db(&db, key.clone(), db_path)?;
            }
            _ => {
                unreachable!();
            }
        }
    }

    Ok(())
}

fn get_entry_mut(db: &mut Database, uuid: u128) -> Option<&mut KEntry> {
    _find_entry_mut(&mut db.root, uuid)
}
fn _find_entry_mut(group: &mut Group, uuid: u128) -> Option<&mut KEntry> {
    for ch in &mut group.children {
        match ch {
            Node::Group(group) => {
                if let Some(entry) = _find_entry_mut(group, uuid) {
                    return Some(entry);
                }
            }
            Node::Entry(entry) => {
                if entry.get_uuid().as_u128() == uuid {
                    return Some(entry);
                }
            }
        }
    }
    None
}

fn save_db(db: &Database, key: DatabaseKey, path: &Path) -> Result<()> {
    // Backup file.
    std::fs::copy(path, path.with_file_name(".backup.kdbx"))?;

    // Write to temporary file first.
    const TEMP_PATH: &str = "/tmp/.pass.kdbx";
    let mut file = File::create(TEMP_PATH)?;
    db.save(&mut file, key.clone())?;

    // Then copy to the target file.
    std::fs::copy(TEMP_PATH, path)?;
    Ok(())
}

fn pick_entry(db: &Database) -> Result<Entry<'_>> {
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

    Ok(entry)
}

fn view_entry(entry: &Entry) -> Result<()> {
    if let Some(username) = entry.username() {
        println!("> Username: {}", username);
    }
    if let Some(url) = entry.url() {
        println!("> Url: {}", url);
    }
    if let Some(notes) = entry.notes() {
        println!("-- Notes ----------------");
        println!("{}", notes);
        println!("-------------------------");
    }

    if let Some(pw) = entry.password() {
        let opts = Options::new();
        opts.copy(
            Source::Bytes(pw.to_string().into_bytes().into()),
            MimeType::Autodetect,
        )?;
        println!("> Copied to clipboard!");
    }

    Ok(())
}

fn new_entry() -> Result<KEntry> {
    let mut entry = KEntry::new();
    let mut edit = EditEntry(&mut entry);

    edit.set_title()?;
    edit.set_username()?;
    edit.set_notes()?;
    edit.set_random_password()?;

    Ok(entry)
}

fn edit_entry(entry: &mut KEntry) -> Result<()> {
    let mut edit = EditEntry(entry);

    loop {
        let action = Select::new(
            ">",
            vec![
                "Title",
                "UserName",
                "Notes",
                "Password (Random)",
                "Password (Manual)",
                "Done",
            ],
        )
        .prompt()?;
        match action {
            "Title" => {
                edit.set_title()?;
            }
            "UserName" => {
                edit.set_username()?;
            }
            "Notes" => {
                edit.set_notes()?;
            }
            "Password (Random)" => {
                edit.set_random_password()?;
            }
            "Password (Manual)" => {
                edit.set_manual_password()?;
            }
            "Done" => {
                break;
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}
