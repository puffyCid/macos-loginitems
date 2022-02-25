use std::env;
use std::io::Write;
use std::{error::Error, fs::OpenOptions};

use csv;
use macos_loginitems::loginitems::LoginItemsResults;

fn main() {
    println!("Starting LoginItems parser...");

    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        let path = &args[1];
        let results = macos_loginitems::parser::parse_loginitems_path(path);
        match results {
            Ok(data) => {
                let mut temp_vec = Vec::new();
                temp_vec.push(data);
                let data_results = parse_data(temp_vec);
                match data_results {
                    Ok(_) => {}
                    Err(error) => println!("Failed to output data: {:?}", error),
                }
            }
            Err(err) => println!("Failed to get loginitem data: {:?}", err),
        }
    } else {
        let results = macos_loginitems::parser::parse_loginitems_system();
        match results {
            Ok(data) => {
                let data_results = parse_data(data);
                match data_results {
                    Ok(_) => {}
                    Err(error) => println!("Failed to output data: {:?}", error),
                }
            }
            Err(err) => println!("Failed to get loginitem data: {:?}", err),
        }
    }
}

fn parse_data(results: Vec<LoginItemsResults>) -> Result<(), Box<dyn Error>> {
    let mut writer = csv::Writer::from_path("output.csv")?;
    let mut json_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("output.json")?;

    writer.write_record(&[
        "Path",
        "CNID Path",
        "Target Creation Timestamp",
        "Volume Path",
        "Volume URL",
        "Volume Name",
        "Volume UUID",
        "Volume Size",
        "Volume Creation",
        "Volume Flags",
        "Volume Root",
        "Localized Name",
        "Security Extension",
        "Target Flags",
        "Creator Username",
        "Creator UID",
        "Folder Index",
        "Creation Options",
        "Is App Bundled",
        "APP ID",
        "APP Binary",
        "Source",
    ])?;

    for result in &results {
        for loginitem in &result.results {
            writer.write_record(&[
                loginitem.path.join("/"),
                format!("{:?}", loginitem.cnid_path),
                loginitem.creation.to_string(),
                loginitem.volume_path.to_string(),
                loginitem.volume_url.to_string(),
                loginitem.volume_name.to_string(),
                loginitem.volume_uuid.to_string(),
                loginitem.volume_size.to_string(),
                loginitem.volume_creation.to_string(),
                format!("{:?}", loginitem.volume_flag),
                loginitem.volume_root.to_string(),
                loginitem.localized_name.to_string(),
                loginitem.security_extension.to_string(),
                format!("{:?}", loginitem.target_flags),
                loginitem.username.to_string(),
                loginitem.uid.to_string(),
                loginitem.folder_index.to_string(),
                loginitem.creation_options.to_string(),
                loginitem.is_bundled.to_string(),
                loginitem.app_id.to_string(),
                loginitem.app_binary.to_string(),
                result.path.to_string(),
            ])?;
        }
    }

    writer.flush()?;
    let serde_data = serde_json::to_string(&results)?;
    json_file.write_all(serde_data.as_bytes())?;
    println!("\nFinished parsing LoginItems data. Saved results to: output.csv and output.json");

    Ok(())
}
