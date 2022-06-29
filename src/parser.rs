use log::{error, warn};
use std::{fs::read_dir, path::Path};

use crate::{
    error::LoginItemError,
    loginitems::{LoginItemsData, LoginItemsResults},
};

pub fn parse_loginitems_system() -> Result<Vec<LoginItemsResults>, LoginItemError> {
    let base_directory = "/Users/";
    let loginitems_path =
        "/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm";

    let mut loginitems_data: Vec<LoginItemsResults> = Vec::new();
    let dir_results = read_dir(base_directory);
    let read_dir = match dir_results {
        Ok(dir) => dir,
        Err(err) => {
            error!("Failed to read base User directory: {:?}", err);
            return Err(LoginItemError::Path);
        }
    };

    for dir in read_dir {
        let entry_result = dir;
        let entry = match entry_result {
            Ok(results) => results,
            Err(err) => {
                warn!("Could not get file entry in base User directory: {:?}", err);
                continue;
            }
        };
        let path = format!("{}{}", entry.path().display(), loginitems_path);
        let full_path = Path::new(&path);

        if full_path.is_file() {
            let plist_path = full_path.display().to_string();
            let results = LoginItemsData::parse_loginitems(&plist_path);
            match results {
                Ok(data) => loginitems_data.push(data),
                Err(err) => return Err(err),
            }
        }
    }

    let mut app_loginitems = LoginItemsData::loginitem_apps_system()?;
    loginitems_data.append(&mut app_loginitems);
    if !loginitems_data.is_empty() {
        return Ok(loginitems_data);
    }

    Ok(loginitems_data)
}

pub fn parse_loginitems_path(path: &str) -> Result<LoginItemsResults, LoginItemError> {
    let results = LoginItemsData::parse_loginitems(path)?;
    Ok(results)
}

pub fn parse_loginitems_bundled_path(path: &str) -> Result<Vec<LoginItemsResults>, LoginItemError> {
    LoginItemsData::loginitems_bundled_apps_path(path)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::parser::parse_loginitems_bundled_path;

    use super::parse_loginitems_path;
    use super::parse_loginitems_system;

    #[test]
    #[ignore = "LoginItems may vary on a live system"]
    fn test_parse_loginitems_system() {
        let results = parse_loginitems_system().unwrap();
        assert!(results.len() > 0);
    }

    #[test]
    fn test_parse_loginitems_path() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/test_data/backgrounditems_sierra.btm");
        let results = parse_loginitems_path(&test_location.display().to_string()).unwrap();
        assert_eq!(results.results.len(), 1);

        assert_eq!(results.results[0].path, ["Applications", "Syncthing.app"]);
        assert_eq!(results.results[0].cnid_path, [103, 706090]);
        assert_eq!(results.results[0].volume_path, "/");
        assert_eq!(results.results[0].volume_url, "file:///");
        assert_eq!(results.results[0].volume_name, "Macintosh HD");
        assert_eq!(
            results.results[0].volume_uuid,
            "0A81F3B1-51D9-3335-B3E3-169C3640360D"
        );
        assert_eq!(results.results[0].volume_size, 160851517440);
        assert_eq!(results.results[0].volume_creation, 241134516.0);
        assert_eq!(results.results[0].volume_flag, [4294967425, 4294972399, 0]);
        assert_eq!(results.results[0].volume_root, true);
        assert_eq!(results.results[0].localized_name, "Syncthing");
        assert_eq!(results.results[0].security_extension, "64cb7eaa9a1bbccc4e1397c9f2a411ebe539cd29;00000000;00000000;0000000000000020;com.apple.app-sandbox.read-write;01;01000004;00000000000ac62a;/applications/syncthing.app\0");
        assert_eq!(results.results[0].target_flags, [2, 15, 0]);
        assert_eq!(results.results[0].username, String::new());
        assert_eq!(results.results[0].folder_index, 0);
        assert_eq!(results.results[0].uid, 0);
        assert_eq!(results.results[0].is_bundled, false);
        assert_eq!(results.results[0].app_id, String::new());
        assert_eq!(results.results[0].app_binary, String::new());
        assert_eq!(results.results[0].created_time, 1651730740);
        assert_eq!(results.results[0].accessed_time, 1651730740);
        assert_eq!(results.results[0].changed_time, 1654739886);
        assert_eq!(results.results[0].modified_time, 1651730740);
    }

    #[test]
    fn test_parse_loginitems_bundled_path() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/test_data/bundled_app");

        let data = parse_loginitems_bundled_path(&test_location.display().to_string()).unwrap();
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
}
