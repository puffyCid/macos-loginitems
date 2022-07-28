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

    assert_eq!(loginitems_data.results[0].creation, creation);
    assert_eq!(loginitems_data.results[0].path, path);
    assert_eq!(loginitems_data.results[0].cnid_path, cnid);
    assert_eq!(loginitems_data.results[0].volume_path, volume_path);
    assert_eq!(loginitems_data.results[0].volume_url, volume_url);
    assert_eq!(loginitems_data.results[0].volume_name, volume_name);
    assert_eq!(loginitems_data.results[0].volume_uuid, volume_uuid);
    assert_eq!(loginitems_data.results[0].volume_creation, volume_creation);
    assert_eq!(loginitems_data.results[0].volume_size, volume_size);
    assert_eq!(loginitems_data.results[0].volume_flag, volume_flags);
    assert_eq!(loginitems_data.results[0].volume_root, volume_root);
    assert_eq!(loginitems_data.results[0].localized_name, localized_name);
    assert_eq!(loginitems_data.results[0].security_extension_rw, extension);
    assert_eq!(loginitems_data.results[0].security_extension_ro, "");
    assert_eq!(loginitems_data.results[0].file_ref_flag, false);

    assert_eq!(loginitems_data.results[0].target_flags, target_flags);
}

#[test]
fn loginitems_poisonapple() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/backgrounditemsPoisonApple.btm");
    let loginitems_data = parse_loginitems_path(&test_location.display().to_string()).unwrap();
    assert_eq!(loginitems_data.results.len(), 3);
    assert_eq!(
        loginitems_data
            .path
            .contains("backgrounditemsPoisonApple.btm"),
        true
    );

    assert_eq!(
        loginitems_data.results[0].path,
        ["Applications", "LuLu.app"]
    );
    assert_eq!(
        loginitems_data.results[0].cnid_path,
        [12884925342, 12885133051]
    );
    assert_eq!(loginitems_data.results[0].volume_path, "/");
    assert_eq!(loginitems_data.results[0].creation, 657495833.0);
    assert_eq!(loginitems_data.results[0].volume_url, "file:///");
    assert_eq!(loginitems_data.results[0].volume_name, "Macintosh HD");
    assert_eq!(
        loginitems_data.results[0].volume_uuid,
        "0A81F3B1-51D9-3335-B3E3-169C3640360D"
    );
    assert_eq!(loginitems_data.results[0].volume_size, 85555372032);
    assert_eq!(
        loginitems_data.results[0].volume_flag,
        [4294967425, 4294972399, 0]
    );
    assert_eq!(loginitems_data.results[0].volume_root, true);
    assert_eq!(loginitems_data.results[0].localized_name, "LuLu");
    assert_eq!(loginitems_data.results[0].security_extension_ro, "");
    assert_eq!(loginitems_data.results[0].security_extension_rw, "");
    assert_eq!(loginitems_data.results[0].target_flags, [530, 543, 538]);
    assert_eq!(loginitems_data.results[0].username, "");
    assert_eq!(loginitems_data.results[0].folder_index, 0);
    assert_eq!(loginitems_data.results[0].uid, 0);
    assert_eq!(loginitems_data.results[0].creation_options, 536870912);
    assert_eq!(loginitems_data.results[0].is_bundled, false);
    assert_eq!(loginitems_data.results[0].app_binary, "");
    assert_eq!(loginitems_data.results[0].app_id, "");
    assert_eq!(loginitems_data.results[0].has_executable_flag, true);
    assert_eq!(loginitems_data.results[0].file_ref_flag, false);

    assert_eq!(
        loginitems_data.results[2].path,
        [
            "Users",
            "sur",
            "Library",
            "Python",
            "3.8",
            "lib",
            "python",
            "site-packages",
            "poisonapple",
            "auxiliary",
            "testing.app"
        ]
    );
    assert_eq!(
        loginitems_data.results[2].cnid_path,
        [
            12884925338,
            12884935193,
            12884935201,
            12885139219,
            12885139220,
            12885139221,
            12885139222,
            12885139223,
            12885139514,
            12885139519,
            12885142308
        ]
    );
    assert_eq!(loginitems_data.results[2].volume_path, "/");
    assert_eq!(loginitems_data.results[2].creation, 678248174.9226916);
    assert_eq!(loginitems_data.results[2].volume_url, "file:///");
    assert_eq!(loginitems_data.results[2].volume_name, "Macintosh HD");
    assert_eq!(
        loginitems_data.results[2].volume_uuid,
        "0A81F3B1-51D9-3335-B3E3-169C3640360D"
    );
    assert_eq!(loginitems_data.results[2].volume_size, 85555372032);
    assert_eq!(
        loginitems_data.results[2].volume_flag,
        [4294967425, 4294972399, 0]
    );
    assert_eq!(loginitems_data.results[2].volume_root, true);
    assert_eq!(loginitems_data.results[2].localized_name, "testing");
    assert_eq!(loginitems_data.results[2].security_extension_ro, "");
    assert_eq!(loginitems_data.results[2].security_extension_rw, "");
    assert_eq!(loginitems_data.results[2].target_flags, [530, 543, 538]);
    assert_eq!(loginitems_data.results[2].username, "sur");
    assert_eq!(loginitems_data.results[2].folder_index, 9);
    assert_eq!(loginitems_data.results[2].uid, 501);
    assert_eq!(loginitems_data.results[2].creation_options, 536870912);
    assert_eq!(loginitems_data.results[2].is_bundled, false);
    assert_eq!(loginitems_data.results[2].app_binary, "");
    assert_eq!(loginitems_data.results[2].app_id, "");
    assert_eq!(loginitems_data.results[2].has_executable_flag, true);
    assert_eq!(loginitems_data.results[2].file_ref_flag, false);
    assert_eq!(loginitems_data.results[2].created_time, 0);
    assert_eq!(loginitems_data.results[2].modified_time, 0);
    assert_eq!(loginitems_data.results[2].accessed_time, 0);
    assert_eq!(loginitems_data.results[2].changed_time, 0);

    assert_eq!(
        loginitems_data.results[1].path,
        ["System", "Library", "CoreServices", "System Events.app"]
    );
    assert_eq!(
        loginitems_data.results[1].cnid_path,
        [
            1152921500311879701,
            1152921500311993981,
            1152921500312123682,
            1152921500312197977
        ]
    );
    assert_eq!(loginitems_data.results[1].volume_path, "/");
    assert_eq!(loginitems_data.results[1].creation, 599558400.0);
    assert_eq!(loginitems_data.results[1].volume_url, "file:///");
    assert_eq!(loginitems_data.results[1].volume_name, "Macintosh HD");
    assert_eq!(
        loginitems_data.results[1].volume_uuid,
        "0A81F3B1-51D9-3335-B3E3-169C3640360D"
    );
    assert_eq!(loginitems_data.results[1].volume_size, 85555372032);
    assert_eq!(
        loginitems_data.results[1].volume_flag,
        [4294967425, 4294972399, 0]
    );
    assert_eq!(loginitems_data.results[1].volume_root, true);
    assert_eq!(loginitems_data.results[1].localized_name, "System Events");
    assert_eq!(loginitems_data.results[1].security_extension_ro, "46d8327f9637aa681e789f0fc10ad53b5ab5343e2ccace15d15e508c16c64fbc;00;00000000;00000000;00000000;000000000000001a;com.apple.app-sandbox.read;01;0100000a;0fffffff0004db59;02;/system/library/coreservices/system events.app\0");
    assert_eq!(loginitems_data.results[1].security_extension_rw, "");
    assert_eq!(loginitems_data.results[1].target_flags, [530, 543, 538]);
    assert_eq!(loginitems_data.results[1].username, "");
    assert_eq!(loginitems_data.results[1].folder_index, 0);
    assert_eq!(loginitems_data.results[1].uid, 0);
    assert_eq!(loginitems_data.results[1].creation_options, 0);
    assert_eq!(loginitems_data.results[1].is_bundled, false);
    assert_eq!(loginitems_data.results[1].app_binary, "");
    assert_eq!(loginitems_data.results[1].app_id, "");
    assert_eq!(loginitems_data.results[1].has_executable_flag, true);
    assert_eq!(loginitems_data.results[1].file_ref_flag, false);
    assert_eq!(loginitems_data.results[1].created_time, 1645859107);
    assert_eq!(loginitems_data.results[1].modified_time, 1645859107);
    assert_eq!(loginitems_data.results[1].accessed_time, 1645859107);
    assert_eq!(loginitems_data.results[1].changed_time, 1645859107);
}

#[test]
fn loginitems_global() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/com.apple.LSSharedFileList.GlobalLoginItems.sfl2");
    let loginitems_data = parse_loginitems_path(&test_location.display().to_string()).unwrap();
    assert_eq!(loginitems_data.results.len(), 2);

    assert_eq!(
        loginitems_data.results[0].path,
        ["Users", "android", "Downloads", "medusa.py"]
    );
}

#[test]
fn loginitems_ventura() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/BackgroundItems-v4.btm");
    let loginitems_data = parse_loginitems_path(&test_location.display().to_string()).unwrap();
    assert_eq!(loginitems_data.results.len(), 1);

    assert_eq!(
        loginitems_data.results[0].path,
        ["Applications", "Syncthing.app"]
    );
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
