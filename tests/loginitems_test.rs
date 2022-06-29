use std::path::PathBuf;

use macos_loginitems::parser::{parse_loginitems_path, parse_loginitems_system};

#[test]
fn loginitems_test() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/backgrounditems_sierra.btm");
    let loginitems_data = parse_loginitems_path(&test_location.display().to_string()).unwrap();
    let creation = 665473989.0;
    let path = ["Applications", "Syncthing.app"];
    let cnid = [103, 706090];
    let volume_path = "/";
    let volume_url = "file:///";
    let volume_name = "Macintosh HD";
    let volume_uuid = "0A81F3B1-51D9-3335-B3E3-169C3640360D";
    let volume_size = 160851517440;
    let volume_creation = 241134516.0;
    let volume_flags = [4294967425, 4294972399, 0];
    let volume_root = true;
    let localized_name = "Syncthing";
    let extension = "64cb7eaa9a1bbccc4e1397c9f2a411ebe539cd29;00000000;00000000;0000000000000020;com.apple.app-sandbox.read-write;01;01000004;00000000000ac62a;/applications/syncthing.app\u{0}";
    let target_flags = [2, 15, 0];

    assert!(loginitems_data.results[0].creation == creation);
    assert!(loginitems_data.results[0].path == path);
    assert!(loginitems_data.results[0].cnid_path == cnid);
    assert!(loginitems_data.results[0].volume_path == volume_path);
    assert!(loginitems_data.results[0].volume_url == volume_url);
    assert!(loginitems_data.results[0].volume_name == volume_name);
    assert!(loginitems_data.results[0].volume_uuid == volume_uuid);
    assert!(loginitems_data.results[0].volume_creation == volume_creation);
    assert!(loginitems_data.results[0].volume_size == volume_size);
    assert!(loginitems_data.results[0].volume_flag == volume_flags);
    assert!(loginitems_data.results[0].volume_root == volume_root);
    assert!(loginitems_data.results[0].localized_name == localized_name);
    assert!(loginitems_data.results[0].security_extension == extension);
    assert!(loginitems_data.results[0].target_flags == target_flags);
}

#[test]
#[ignore = "LoginItems may vary on a live system"]
fn loginitems_system() {
    let results = parse_loginitems_system().unwrap();
    assert!(results.len() > 0);
}

#[test]
#[should_panic(expected = "Plist")]
fn malformed_plist_test() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/malformed/bad_plist.btm");
    let _ = parse_loginitems_path(&test_location.display().to_string()).unwrap();
}

#[test]
#[should_panic(expected = "Bookmark")]
fn malformed_bookmark_test() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/malformed/bad_bookmark.btm");
    let _ = parse_loginitems_path(&test_location.display().to_string()).unwrap();
}
