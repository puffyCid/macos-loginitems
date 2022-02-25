use std::{
    error,
    fs::read_dir,
    io::{Error, ErrorKind},
    path::Path,
};

use crate::loginitems::{LoginItemsData, LoginItemsResults};

pub fn parse_loginitems_system() -> Result<Vec<LoginItemsResults>, Box<dyn error::Error + 'static>>
{
    let base_directory = "/Users/";
    let loginitems_path =
        "/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm";

    let mut loginitems_data: Vec<LoginItemsResults> = Vec::new();
    for dir in read_dir(base_directory)? {
        let entry = dir?;
        let path = format!("{}{}", entry.path().display(), loginitems_path);
        let full_path = Path::new(&path);

        if full_path.is_file() {
            let plist_path = full_path.display().to_string();
            let results = LoginItemsData::parse_loginitems(&plist_path);
            match results {
                Ok(data) => loginitems_data.push(data),
                Err(err) => {
                    return Err(Box::new(Error::new(
                        ErrorKind::InvalidInput,
                        format!("{:?}", err),
                    )))
                }
            }
        }
    }
    let mut app_loginitems = LoginItemsData::loginitem_apps()?;
    loginitems_data.append(&mut app_loginitems);
    if !loginitems_data.is_empty() {
        return Ok(loginitems_data);
    }
    Err(Box::new(Error::new(
        ErrorKind::InvalidInput,
        "No bookmark files on system".to_string(),
    )))
}

pub fn parse_loginitems_path(path: &str) -> Result<LoginItemsResults, Box<dyn error::Error + '_>> {
    let results = LoginItemsData::parse_loginitems(path)?;
    Ok(results)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::parse_loginitems_path;
    use super::parse_loginitems_system;

    #[test]
    #[ignore = "Parse loginitems on live system"]
    fn test_parse_loginitems_system() {
        let results = parse_loginitems_system().unwrap();
        assert!(results.len() > 0);
    }

    #[test]
    fn test_parse_loginitems_path() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/test_data/backgrounditems_sierra.btm");
        let results = parse_loginitems_path(&test_location.display().to_string()).unwrap();
        assert!(results.results.len() == 1);
    }
}
