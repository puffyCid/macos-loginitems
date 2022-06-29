//! Parse macOS LoginItems data
//!
//! Provides a library to parse LoginItems data.

use log::{error, info, warn};
use std::fs::{self, Metadata};
use std::io::{Error, ErrorKind};
use std::{fs::read_dir, os::macos::fs::MetadataExt, path::Path};

use serde::Serialize;

use crate::error::LoginItemError;
use crate::loginitems_plist;

#[derive(Debug, Serialize)]
pub struct LoginItemsResults {
    pub results: Vec<LoginItemsData>,
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct LoginItemsData {
    pub path: Vec<String>,          // Path to binary to run
    pub cnid_path: Vec<i64>,        // Path represented as Catalog Node ID
    pub creation: f64,              // Created timestamp of binary target
    pub volume_path: String,        // Root
    pub volume_url: String,         // URL type
    pub volume_name: String,        // Name of Volume
    pub volume_uuid: String,        // Volume UUID string
    pub volume_size: i64,           // Size of Volume
    pub volume_creation: f64,       // Created timestamp of Volume
    pub volume_flag: Vec<u64>,      // Volume Property flags
    pub volume_root: bool,          // If Volume is filesystem root
    pub localized_name: String,     // Optional localized name of target binary
    pub security_extension: String, // Optional Security extension of target binary
    pub target_flags: Vec<u64>,     // Resource property flags
    pub username: String,           // Username related to bookmark
    pub folder_index: i64,          // Folder index number
    pub uid: i32,                   // User UID
    pub creation_options: i32,      // Bookmark creation options
    pub is_bundled: bool,           // Is loginitem in App
    pub app_id: String,             // App ID
    pub app_binary: String,         // App binary
    pub has_executable_flag: bool,  // Can loginitem be executed
    pub created_time: i64,
    pub modified_time: i64,
    pub accessed_time: i64,
    pub changed_time: i64,
}

impl LoginItemsData {
    /// Parse User LoginItems from provided path
    pub fn parse_loginitems(path: &str) -> Result<LoginItemsResults, LoginItemError> {
        // Parse PLIST file and get any bookmark data
        let loginitems_results = loginitems_plist::get_bookmarks(path);

        let loginitems_data = match loginitems_results {
            Ok(data) => data,
            Err(err) => {
                error!("Failed to read loginitem PLIST file {:?}: {:?}", path, err);
                return Err(LoginItemError::Plist);
            }
        };
        if loginitems_data.is_empty() {
            info!("No loginitems found");
            let loginitems_empty = LoginItemsResults {
                results: Vec::new(),
                path: String::new(),
            };
            return Ok(loginitems_empty);
        }

        let mut loginitems_results = LoginItemsResults {
            results: Vec::new(),
            path: String::new(),
        };
        for data in loginitems_data {
            let results = macos_bookmarks::parser::parse_bookmark(&data);
            let bookmark = match results {
                Ok(bookmark_data) => bookmark_data,
                Err(err) => {
                    error!("Failed to parse bookmark data: {:?}", err);
                    return Err(LoginItemError::Bookmark);
                }
            };
            let mut loginitem_data = LoginItemsData {
                path: bookmark.path,
                cnid_path: bookmark.cnid_path,
                creation: bookmark.creation,
                volume_path: bookmark.volume_path,
                volume_url: bookmark.volume_url,
                volume_name: bookmark.volume_name,
                volume_uuid: bookmark.volume_uuid,
                volume_size: bookmark.volume_size,
                volume_creation: bookmark.volume_creation,
                volume_flag: bookmark.volume_flag,
                volume_root: bookmark.volume_root,
                localized_name: bookmark.localized_name,
                security_extension: bookmark.security_extension,
                target_flags: bookmark.target_flags,
                username: bookmark.username,
                folder_index: bookmark.folder_index,
                uid: bookmark.uid,
                creation_options: bookmark.creation_options,
                is_bundled: false,
                app_id: String::new(),
                app_binary: String::new(),
                created_time: 0,
                modified_time: 0,
                accessed_time: 0,
                changed_time: 0,
                has_executable_flag: bookmark.is_executable,
            };
            let app_path = format!("/{}", loginitem_data.path.join("/"));
            let metadata_results = LoginItemsData::timestamps(&app_path);
            match metadata_results {
                Ok(metadata) => {
                    loginitem_data.created_time = metadata.st_birthtime();
                    loginitem_data.modified_time = metadata.st_mtime();
                    loginitem_data.accessed_time = metadata.st_atime();
                    loginitem_data.changed_time = metadata.st_ctime();
                }
                Err(err) => error!(
                    "Failed to get timestamps associated with loginitem {:?}: {:?}",
                    app_path, err
                ),
            }

            loginitems_results.results.push(loginitem_data);
        }
        loginitems_results.path = path.to_string();

        Ok(loginitems_results)
    }

    pub fn loginitems_bundled_apps_path(
        path: &str,
    ) -> Result<Vec<LoginItemsResults>, LoginItemError> {
        let mut loginitems_vec: Vec<LoginItemsResults> = Vec::new();

        let dir_results = read_dir(path);
        let read_dir = match dir_results {
            Ok(dir) => dir,
            Err(err) => {
                error!("Failed to read LoginItem bundled App directory: {:?}", err);
                return Err(LoginItemError::Path);
            }
        };

        for dir in read_dir {
            let mut loginitems = LoginItemsResults {
                results: Vec::new(),
                path: String::new(),
            };

            let entry_result = dir;
            let entry = match entry_result {
                Ok(results) => results,
                Err(err) => {
                    warn!(
                        "Could not get file entry in bundled App LoginItem directory: {:?}",
                        err
                    );
                    continue;
                }
            };

            let path = format!("{}", entry.path().display());

            if !path.contains("loginitems") {
                continue;
            }

            let loginitems_plist: Result<plist::Dictionary, plist::Error> = plist::from_file(path);
            match loginitems_plist {
                Ok(data) => {
                    for (key, value) in data {
                        let mut loginitems_data = LoginItemsData {
                            path: Vec::new(),
                            cnid_path: Vec::new(),
                            creation: 0.0,
                            volume_path: String::new(),
                            volume_url: String::new(),
                            volume_name: String::new(),
                            volume_uuid: String::new(),
                            volume_size: 0,
                            volume_creation: 0.0,
                            volume_flag: Vec::new(),
                            volume_root: false,
                            localized_name: String::new(),
                            security_extension: String::new(),
                            target_flags: Vec::new(),
                            username: String::new(),
                            folder_index: 0,
                            uid: 0,
                            creation_options: 0,
                            is_bundled: true,
                            app_id: String::new(),
                            app_binary: String::new(),
                            created_time: 0,
                            modified_time: 0,
                            accessed_time: 0,
                            changed_time: 0,
                            has_executable_flag: false,
                        };

                        if key.starts_with("version") {
                            continue;
                        }

                        let id_results = value.into_string();
                        match id_results {
                            Some(app_id) => loginitems_data.app_id = app_id,
                            None => warn!("No app id associated with bundled loginitem"),
                        }

                        loginitems_data.app_binary = key;
                        loginitems.results.push(loginitems_data);
                        loginitems.path = entry.path().display().to_string();
                    }
                }
                Err(err) => {
                    warn!(
                        "Failed to parse PLIST file: {:?} {:?}",
                        entry.path().display(),
                        err
                    );
                }
            }
            loginitems_vec.push(loginitems);
        }

        Ok(loginitems_vec)
    }

    /// Get loginitem data from embedded loginitems in Apps
    pub fn loginitem_apps_system() -> Result<Vec<LoginItemsResults>, LoginItemError> {
        let default_path = "/var/db/com.apple.xpc.launchd/";
        LoginItemsData::loginitems_bundled_apps_path(default_path)
    }

    fn timestamps(path: &str) -> Result<Metadata, std::io::Error> {
        if !Path::exists(Path::new(path)) {
            return Err(Error::new(ErrorKind::InvalidInput, "path not found"));
        }
        fs::metadata(path)
    }
}

#[cfg(test)]
mod tests {

    use std::{os::macos::fs::MetadataExt, path::PathBuf};

    use super::LoginItemsData;

    #[test]
    #[ignore = "Bundled LoginItems may not exist on live system"]
    fn test_loginitem_apps_system() {
        let data = LoginItemsData::loginitem_apps_system().unwrap();
        assert!(data.len() >= 1);
    }

    #[test]
    fn test_loginitems_bundled_apps_path() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/test_data/bundled_app");

        let data =
            LoginItemsData::loginitems_bundled_apps_path(&test_location.display().to_string())
                .unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].results.len(), 2);
        assert_eq!(data[0].results[0].is_bundled, true);
        assert_eq!(data[0].results[0].app_binary, "com.docker.helper");
        assert_eq!(data[0].results[0].app_id, "com.docker.docker");

        assert_eq!(data[0].results[1].is_bundled, true);
        assert_eq!(
            data[0].results[1].app_binary,
            "com.csaba.fitzl.shield.ShieldHelper"
        );
        assert_eq!(data[0].results[1].app_id, "com.csaba.fitzl.shield");
    }

    #[test]
    fn test_parse_loginitems() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/test_data/backgrounditems_sierra.btm");
        let data = LoginItemsData::parse_loginitems(&test_location.display().to_string()).unwrap();

        assert_eq!(data.results.len(), 1);
        assert_eq!(data.results[0].path, ["Applications", "Syncthing.app"]);
        assert_eq!(data.results[0].cnid_path, [103, 706090]);
        assert_eq!(data.results[0].volume_path, "/");
        assert_eq!(data.results[0].volume_url, "file:///");
        assert_eq!(data.results[0].volume_name, "Macintosh HD");
        assert_eq!(
            data.results[0].volume_uuid,
            "0A81F3B1-51D9-3335-B3E3-169C3640360D"
        );
        assert_eq!(data.results[0].volume_size, 160851517440);
        assert_eq!(data.results[0].volume_creation, 241134516.0);
        assert_eq!(data.results[0].volume_flag, [4294967425, 4294972399, 0]);
        assert_eq!(data.results[0].volume_root, true);
        assert_eq!(data.results[0].localized_name, "Syncthing");
        assert_eq!(data.results[0].security_extension, "64cb7eaa9a1bbccc4e1397c9f2a411ebe539cd29;00000000;00000000;0000000000000020;com.apple.app-sandbox.read-write;01;01000004;00000000000ac62a;/applications/syncthing.app\0");
        assert_eq!(data.results[0].target_flags, [2, 15, 0]);
        assert_eq!(data.results[0].username, String::new());
        assert_eq!(data.results[0].folder_index, 0);
        assert_eq!(data.results[0].uid, 0);
        assert_eq!(data.results[0].is_bundled, false);
        assert_eq!(data.results[0].app_id, String::new());
        assert_eq!(data.results[0].app_binary, String::new());
        assert_eq!(data.results[0].created_time, 1651730740);
        assert_eq!(data.results[0].accessed_time, 1651730740);
        assert_eq!(data.results[0].changed_time, 1654739886);
        assert_eq!(data.results[0].modified_time, 1651730740);
        assert_eq!(data.results[0].has_executable_flag, false);
    }

    #[test]
    fn test_timestamps() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/test_data/backgrounditems_sierra.btm");
        let data = LoginItemsData::timestamps(&test_location.display().to_string()).unwrap();

        assert!(data.st_birthtime() > 1644385700);
        assert!(data.st_atime() > 1644385700);
        assert!(data.st_ctime() > 1644385700);
        assert!(data.st_mtime() > 1644385700);
    }
}
