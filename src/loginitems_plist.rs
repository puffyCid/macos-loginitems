//! Parse macOS LoginItems data
//!
//! Provides a library to parse LoginItems data.

use log::warn;
use plist::{Dictionary, Value};

/// Parse PLIST file and get Vec of bookmark data
pub fn get_bookmarks(path: &str) -> Result<Vec<Vec<u8>>, plist::Error> {
    let login_items: Dictionary = plist::from_file(path)?;
    for (key, value) in login_items {
        if key != "$objects" {
            continue;
        }
        match value {
            Value::Array(value_array) => {
                let results = get_array_values(value_array)?;
                return Ok(results);
            }
            _ => {
                warn!("Empty PLIST Array data");
            }
        }
    }
    let empty_bookmark: Vec<Vec<u8>> = Vec::new();
    Ok(empty_bookmark)
}

/// Loop through Array values and identify bookmark data (should be at least 48 bytes in size (header is 48 bytes))
fn get_array_values(data_results: Vec<Value>) -> Result<Vec<Vec<u8>>, plist::Error> {
    let mut bookmark_data: Vec<Vec<u8>> = Vec::new();
    for data in data_results {
        match data {
            Value::Data(_) => {
                let plist_data = data.as_data();
                match plist_data {
                    Some(plist_results) => bookmark_data.push(plist_results.to_vec()),
                    None => {
                        warn!("No PLIST data")
                    }
                }
            }

            Value::Dictionary(_) => {
                let dict_bookmark = data.as_dictionary();
                match dict_bookmark {
                    Some(dict) => {
                        for (_dict_key, dict_data) in dict {
                            match dict_data {
                                Value::Data(_) => {
                                    let plist_data = dict_data.as_data();
                                    match plist_data {
                                        Some(plist_results) => {
                                            let min_bookmark_size = 48;
                                            if plist_results.len() < min_bookmark_size {
                                                continue;
                                            }
                                            bookmark_data.push(plist_results.to_vec())
                                        }
                                        None => {
                                            warn!("No PLIST data in dictionary")
                                        }
                                    }
                                }
                                _ => continue,
                            }
                        }
                    }
                    None => continue,
                }
            }
            _ => continue,
        }
    }

    Ok(bookmark_data)
}

#[cfg(test)]
mod tests {
    use super::{get_array_values, get_bookmarks};
    use plist::{Dictionary, Value};
    use std::path::PathBuf;

    #[test]
    fn test_get_bookmarks() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/test_data/backgrounditems_sierra.btm");

        let bookmarks = get_bookmarks(&test_location.display().to_string()).unwrap();
        assert!(bookmarks.len() == 1);
    }

    #[test]
    fn test_get_array_values() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/test_data/backgrounditems_sierra.btm");

        let login_items: Dictionary =
            plist::from_file(test_location.display().to_string()).unwrap();

        let mut results: Vec<Vec<u8>> = Vec::new();
        for (key, value) in login_items {
            if key.as_str() != "$objects" {
                continue;
            }
            match value {
                Value::Array(value_array) => {
                    results = get_array_values(value_array).unwrap();
                }
                _ => {
                    panic!("Unsupported Value type, expected array. Got: {:?}", value)
                }
            }
        }
        assert!(results.len() == 1);
    }
}
