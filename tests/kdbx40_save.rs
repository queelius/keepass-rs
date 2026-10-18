//! Saving KDBX 4.0 databases (sseemayer/keepass-rs#373).
//!
//! A KDBX 4.0 database is saved as KDBX 4.0, unless it holds data that only
//! KDBX 4.1 can represent, in which case it is saved as KDBX 4.1 so that the
//! data is not dropped. A KDBX 4.1 database is always saved as KDBX 4.1.
//! See <https://keepass.info/help/kb/kdbx_4.1.html> for the 4.1 additions.

#![cfg(feature = "save_kdbx4")]
#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use keepass::{
    config::DatabaseVersion,
    db::{CustomDataItem, CustomDataValue, Database, DatabaseSaveError, EntryId},
    DatabaseKey,
};
use quick_xml::{events::Event, Reader};

const PASSWORD: &str = "demopass";

/// KDBX 4.0 fixtures (all with password `demopass`), covering different KDFs, ciphers and
/// deleted objects.
const KDBX40_FIXTURES: &[&str] = &[
    "tests/resources/test_db_kdbx4_with_password_argon2.kdbx",
    "tests/resources/test_db_kdbx4_with_password_argon2id_chacha20.kdbx",
    "tests/resources/test_db_kdbx4_with_password_argon2_twofish.kdbx",
    "tests/resources/test_db_kdbx4_with_password_deleted_entry.kdbx",
];

const KDBX41_FIXTURE: &str = "tests/resources/test_db_kdbx41_features.kdbx";

/// XML elements that KDBX 4.1 added, as (parent element, element) pairs.
const KDBX41_ONLY_ELEMENTS: &[(&str, &str)] = &[
    ("Group", "Tags"),
    ("Group", "PreviousParentGroup"),
    ("Entry", "QualityCheck"),
    ("Entry", "PreviousParentGroup"),
    ("Icon", "Name"),
    ("Icon", "LastModificationTime"),
    // `Item` only occurs inside `CustomData`
    ("Item", "LastModificationTime"),
];

fn key() -> DatabaseKey {
    DatabaseKey::new().with_password(PASSWORD)
}

fn open_fixture(path: &str) -> Database {
    let mut file = std::fs::File::open(path).expect("open fixture");
    Database::open(&mut file, key()).expect("parse fixture")
}

fn save(db: &Database) -> Vec<u8> {
    let mut buf = Vec::new();
    db.save(&mut buf, key()).expect("save");
    buf
}

fn reopen(saved: &[u8]) -> Database {
    Database::open(&mut &saved[..], key()).expect("reopen saved database")
}

/// Read the (major, minor) file version from the first 12 bytes of a saved KDBX file.
fn header_version(saved: &[u8]) -> (u16, u16) {
    let minor = u16::from_le_bytes([saved[8], saved[9]]);
    let major = u16::from_le_bytes([saved[10], saved[11]]);
    (major, minor)
}

/// List the KDBX 4.1-only elements present in the decrypted XML of a saved file, as
/// `parent/element` strings.
fn kdbx41_only_elements(saved: &[u8]) -> Vec<String> {
    let xml = Database::get_xml(&mut &saved[..], key()).expect("decrypt saved database");

    let mut reader = Reader::from_reader(&xml[..]);
    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut found = Vec::new();

    let mut check = |stack: &[String], name: &str| {
        if let Some(parent) = stack.last() {
            if KDBX41_ONLY_ELEMENTS.contains(&(parent.as_str(), name)) {
                found.push(format!("{parent}/{name}"));
            }
        }
    };

    loop {
        match reader.read_event_into(&mut buf).expect("well-formed XML") {
            Event::Start(e) => {
                let name = e.name().as_ref().to_string();
                check(&stack, &name);
                stack.push(name);
            }
            Event::Empty(e) => {
                let name = e.name().as_ref().to_string();
                check(&stack, &name);
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    found
}

/// Adds one kind of KDBX 4.1-only data to a database.
type AddKdbx41Data = Box<dyn Fn(&mut Database)>;

fn first_entry_id(db: &Database) -> EntryId {
    db.root().entries().next().expect("fixture has an entry").id()
}

#[test]
fn kdbx40_fixtures_save_as_kdbx40_and_round_trip() {
    for path in KDBX40_FIXTURES {
        let db = open_fixture(path);
        assert_eq!(db.config.version, DatabaseVersion::KDB4(0), "{path}");

        let saved = save(&db);
        assert_eq!(header_version(&saved), (4, 0), "{path}: header must say KDBX 4.0");

        let reopened = reopen(&saved);
        assert_eq!(reopened.config.version, DatabaseVersion::KDB4(0), "{path}");
        assert_eq!(reopened, db, "{path}: content changed across save");
    }
}

#[test]
fn kdbx40_save_writes_no_kdbx41_elements() {
    for path in KDBX40_FIXTURES {
        let saved = save(&open_fixture(path));
        assert_eq!(
            kdbx41_only_elements(&saved),
            Vec::<String>::new(),
            "{path}: a KDBX 4.0 file must not contain KDBX 4.1 elements"
        );
    }
}

#[test]
fn kdbx40_with_kdbx41_data_saves_as_kdbx41() {
    let fixed_time = chrono::NaiveDate::from_ymd_opt(2024, 6, 15)
        .unwrap()
        .and_hms_opt(12, 30, 45)
        .unwrap();

    let cases: Vec<(&str, AddKdbx41Data)> = vec![
        (
            "group tags",
            Box::new(|db| db.root_mut().tags = vec!["tagged".to_string()]),
        ),
        (
            "entry quality check disabled",
            Box::new(|db| {
                let id = first_entry_id(db);
                db.entry_mut(id).unwrap().quality_check = false;
            }),
        ),
        (
            "quality check disabled only in history",
            Box::new(|db| {
                let id = first_entry_id(db);
                let mut entry = db.entry_mut(id).unwrap();
                entry.quality_check = false;
                entry.edit_tracking(|e| e.as_mut().quality_check = true);
            }),
        ),
        (
            "entry previous parent group",
            Box::new(|db| {
                let id = first_entry_id(db);
                let group_id = db.root_mut().add_group().id();
                db.entry_mut(id).unwrap().move_to(group_id).unwrap();
            }),
        ),
        (
            "group previous parent group",
            Box::new(|db| {
                let (first, second) = {
                    let mut root = db.root_mut();
                    let first = root.add_group().id();
                    let second = root.add_group().id();
                    (first, second)
                };
                db.group_mut(second).unwrap().move_to(first).unwrap();
            }),
        ),
        (
            "named custom icon",
            Box::new(|db| {
                let id = db.root_mut().set_icon_custom_new(vec![1, 2, 3]).id();
                let mut icon = db.custom_icon_mut(id).unwrap();
                icon.name = Some("icon".to_string());
                icon.last_modification_time = None;
            }),
        ),
        (
            "custom icon modification time",
            Box::new(|db| {
                db.root_mut().set_icon_custom_new(vec![1, 2, 3]);
            }),
        ),
        (
            "meta custom data modification time",
            Box::new(move |db| {
                db.meta.custom_data.insert(
                    "key".to_string(),
                    CustomDataItem {
                        value: Some(CustomDataValue::String("value".to_string())),
                        last_modification_time: Some(fixed_time),
                    },
                );
            }),
        ),
        (
            "group custom data modification time",
            Box::new(move |db| {
                db.root_mut().custom_data.insert(
                    "key".to_string(),
                    CustomDataItem {
                        value: Some(CustomDataValue::String("value".to_string())),
                        last_modification_time: Some(fixed_time),
                    },
                );
            }),
        ),
        (
            "entry custom data modification time",
            Box::new(move |db| {
                let id = first_entry_id(db);
                db.entry_mut(id).unwrap().custom_data.insert(
                    "key".to_string(),
                    CustomDataItem {
                        value: Some(CustomDataValue::String("value".to_string())),
                        last_modification_time: Some(fixed_time),
                    },
                );
            }),
        ),
    ];

    for (name, add_kdbx41_data) in cases {
        let mut db = open_fixture(KDBX40_FIXTURES[0]);
        add_kdbx41_data(&mut db);
        assert_eq!(db.config.version, DatabaseVersion::KDB4(0), "{name}");

        let saved = save(&db);
        assert_eq!(
            header_version(&saved),
            (4, 1),
            "{name}: must be upgraded to KDBX 4.1"
        );
        assert!(
            !kdbx41_only_elements(&saved).is_empty(),
            "{}: the KDBX 4.1 data must be written",
            name
        );

        let mut reopened = reopen(&saved);
        assert_eq!(reopened.config.version, DatabaseVersion::KDB4(1), "{name}");

        // apart from the version, nothing may change
        reopened.config.version = DatabaseVersion::KDB4(0);
        assert_eq!(reopened, db, "{name}: content changed across save");
    }
}

#[test]
fn kdbx41_fixture_still_saves_as_kdbx41() {
    let db = open_fixture(KDBX41_FIXTURE);
    assert_eq!(db.config.version, DatabaseVersion::KDB4(1));

    let saved = save(&db);
    assert_eq!(header_version(&saved), (4, 1));
    assert!(!kdbx41_only_elements(&saved).is_empty());

    let reopened = reopen(&saved);
    assert_eq!(reopened.config.version, DatabaseVersion::KDB4(1));
    assert_eq!(reopened, db);
}

#[test]
fn kdbx41_without_kdbx41_data_is_not_downgraded() {
    let db = open_fixture(KDBX40_FIXTURES[0]);
    let mut db41 = db.clone();
    db41.config.version = DatabaseVersion::KDB4(1);

    let saved = save(&db41);
    assert_eq!(header_version(&saved), (4, 1));
    assert_eq!(reopen(&saved).config.version, DatabaseVersion::KDB4(1));
}

#[test]
fn unknown_kdbx4_minor_version_is_rejected() {
    let mut db = open_fixture(KDBX40_FIXTURES[0]);
    db.config.version = DatabaseVersion::KDB4(2);

    let result = db.save(&mut Vec::new(), key());
    assert!(matches!(result, Err(DatabaseSaveError::UnsupportedVersion)));
}
