//! Parse macOS LoginItems data
//!
//! Provides a library to parse LoginItems data.

use std::{
    error,
    fs::read_dir,
    io::{Error, ErrorKind},
    mem::size_of,
    path::Path,
    str::{from_utf8, Utf8Error},
};

use log::{info, warn};
use nom::{
    bytes::streaming::take,
    number::streaming::be_u32,
    number::{complete::be_f64, streaming::le_u64},
    number::{complete::le_i32, streaming::le_u16},
    number::{complete::le_i64, streaming::le_u32},
};
use serde::Serialize;

use crate::loginitems_plist;

#[derive(Debug, Serialize)]
pub struct LoginItemsResults {
    pub results: Vec<LoginItemsData>,
    pub path: String,
}

// Bookmark documentation:
// https://mac-alias.readthedocs.io/en/latest/bookmark_fmt.html
// http://michaellynn.github.io/2015/10/24/apples-bookmarkdata-exposed/
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
    pub folder_index: i32,          // Folder index number
    pub uid: i32,                   // User UID
    pub creation_options: i32,      // Bookmark creation options
    pub is_bundled: bool,           // Is loginitem in App
    pub app_id: String,             // App ID
    pub app_binary: String,         // App binary
}

#[derive(Debug)]
struct BookmarkHeader {
    signature: u32,            // Bookmark Signature "book"
    bookmark_data_length: u32, // Total size of bookmark
    version: u32,              // Possible version number
    bookmark_data_offset: u32, // Offset to start of bookmark data (always 0x30 (48)).
                               // Followed by 32 bytes of empty/reserved space (48 bytes total)
}

#[derive(Debug)]
struct BookmarkData {
    table_of_contents_offset: u32, // Offset to start of Table of Contents (TOC)
}

#[derive(Debug)]
struct TableOfContentsHeader {
    data_length: u32, // Size of TOC
    record_type: u16, // Unused TOC record/key type (Possible magic number along side flags (0xfffffffe))
    flags: u16,       // Unused flag (Possible magic number along side record_type (0xfffffffe))
}

#[derive(Debug)]
struct TableOfContentsData {
    level: u32,              // TOC Data level or identifier (always 1?)
    next_record_offset: u32, // Offset to next TOC record
    number_of_records: u32,  // Number of records in TOC
}

#[derive(Debug)]
struct TableOfContentsDataRecord {
    record_type: u32, // Record/Key type
    data_offset: u32, // Offset to record data
    reserved: u32,    // Reserved (0)
}

#[derive(Debug)]
struct StandardDataRecord {
    data_length: u32,     // Length of data
    data_type: u32,       // Type of data
    record_data: Vec<u8>, // Data
    record_type: u32,     // Record type (from TableOfContentsDataRecord)
}

impl LoginItemsData {
    // Data types
    const STRING_TYPE: u32 = 0x0101;
    const DATA_TYPE: u32 = 0x0201;
    const _NUMBER_ONE_BYTE: u32 = 0x0301;
    const _NUMBER_TWO_BYTE: u32 = 0x0302;
    const NUMBER_FOUR_BYTE: u32 = 0x0303;
    const NUMBER_EIGHT_BYTE: u32 = 0x0304;
    const _NUMBER_FLOAT: u32 = 0x0305;
    const _NUMBERBER_FLOAT64: u32 = 0x0306;
    const DATE: u32 = 0x0400;
    const _BOOL_FALSE: u32 = 0x0500;
    const BOOL_TRUE: u32 = 0x0501;
    const ARRAY_TYPE: u32 = 0x0601;
    const _DICTIONARY: u32 = 0x0701;
    const _UUID: u32 = 0x0801;
    const URL: u32 = 0x0901;
    const _URL_RELATIVE: u32 = 0x0902;

    // Table of Contents Key types
    const _UNKNOWN: u32 = 0x1003;
    const TARGET_PATH: u32 = 0x1004;
    const TARGET_CNID_PATH: u32 = 0x1005;
    const TARGET_FLAGS: u32 = 0x1010;
    const _TARGET_FILENAME: u32 = 0x1020;
    const TARGET_CREATION_DATE: u32 = 0x1040;
    const _UKNOWN2: u32 = 0x1054;
    const _UNKNOWN3: u32 = 0x1055;
    const _UNKNOWN4: u32 = 0x1056;
    const _UNKNOWN5: u32 = 0x1057;
    const _UNKNOWN6: u32 = 0x1101;
    const _UNKNOWN7: u32 = 0x1102;
    const _TOC_PATH: u32 = 0x2000;
    const VOLUME_PATH: u32 = 0x2002;
    const VOLUME_URL: u32 = 0x2005;
    const VOLUME_NAME: u32 = 0x2010;
    const VOLUME_UUID: u32 = 0x2011;
    const VOLUME_SIZE: u32 = 0x2012;
    const VOLUME_CREATION: u32 = 0x2013;
    const _VOLUME_BOOKMARK: u32 = 0x2040;
    const VOLUME_FLAGS: u32 = 0x2020;
    const VOLUME_ROOT: u32 = 0x2030;
    const _VOLUME_MOUNT_POINT: u32 = 0x2050;
    const _UNKNOWN8: u32 = 0x2070;
    const CONTAIN_FOLDER_INDEX: u32 = 0xc001;
    const CREATOR_USERNAME: u32 = 0xc011;
    const CREATOR_UID: u32 = 0xc012;
    const _FILE_REF_FLAG: u32 = 0xd001;
    const CREATION_OPTIONS: u32 = 0xd010;
    const _URL_LENGTH_ARRAY: u32 = 0xe003;
    const LOCALIZED_NAME: u32 = 0xf017;
    const _UNKNOWN9: u32 = 0xf022;
    const SECURITY_EXTENSION: u32 = 0xf080;
    const _UNKNOWN10: u32 = 0xf081;

    /// Parse loginitems from provided input path
    pub fn parse_loginitems(path: &str) -> Result<LoginItemsResults, Box<dyn error::Error + '_>> {
        // Parse PLIST file and get any bookmark data
        let loginitems_data = loginitems_plist::get_bookmarks(path)?;
        if loginitems_data.is_empty() {
            info!("No loginitems found");
            let loginitems_empty = LoginItemsResults {
                results: Vec::new(),
                path: String::new(),
            };
            return Ok(loginitems_empty);
        }

        let mut loginitems_array: Vec<LoginItemsData> = Vec::new();
        // Loop through all bookmark data found in PLIST
        for data in loginitems_data {
            let results = LoginItemsData::bookmark_header(&data);
            match results {
                Ok((bookmark_data, bookmark_header)) => {
                    let book_sig: u32 = 1802465122;
                    let book_data_offset: u32 = 48;

                    // Check for bookmark signature and expected offset
                    if bookmark_header.signature != book_sig
                        || bookmark_header.bookmark_data_offset != book_data_offset
                    {
                        warn!("Not a bookmark file: {:?}", path);
                        continue;
                    }
                    let bookmark_results = LoginItemsData::bookmark_data(bookmark_data);
                    match bookmark_results {
                        Ok((_, bookmark_loginitems)) => {
                            loginitems_array.push(bookmark_loginitems);
                        }
                        Err(err) => {
                            return Err(Box::new(Error::new(
                                ErrorKind::InvalidInput,
                                format!("Failed to parse bookmark data: {:?}", err),
                            )))
                        }
                    }
                }
                Err(err) => {
                    return Err(Box::new(Error::new(
                        ErrorKind::InvalidInput,
                        format!("Failed to parser bookmark header: {:?}", err),
                    )))
                }
            }
        }
        let loginitems_data = LoginItemsResults {
            results: loginitems_array,
            path: path.to_string(),
        };
        Ok(loginitems_data)
    }

    /// Parse bookmark header
    fn bookmark_header(data: &[u8]) -> nom::IResult<&[u8], BookmarkHeader> {
        let mut bookmark_header = BookmarkHeader {
            signature: 0,
            bookmark_data_length: 0,
            version: 0,
            bookmark_data_offset: 0,
        };

        let (input, sig) = take(size_of::<u32>())(data)?;
        let (input, data_length) = take(size_of::<u32>())(input)?;
        let (input, version) = take(size_of::<u32>())(input)?;
        let (input, data_offset) = take(size_of::<u32>())(input)?;

        let filler_size: u32 = 32;
        let (input, _) = take(filler_size)(input)?;

        let (_, bookmark_sig) = le_u32(sig)?;
        let (_, bookmark_data_length) = le_u32(data_length)?;
        let (_, bookmark_version) = be_u32(version)?;
        let (_, bookmark_data_offset) = le_u32(data_offset)?;

        bookmark_header.signature = bookmark_sig;
        bookmark_header.bookmark_data_length = bookmark_data_length;
        bookmark_header.version = bookmark_version;
        bookmark_header.bookmark_data_offset = bookmark_data_offset;
        Ok((input, bookmark_header))
    }

    /// Parse the core bookmark data
    fn bookmark_data(data: &[u8]) -> nom::IResult<&[u8], LoginItemsData> {
        let mut book_data = BookmarkData {
            table_of_contents_offset: 0,
        };

        let (input, offset) = take(size_of::<u32>())(data)?;
        let (_, toc_offset) = le_u32(offset)?;

        book_data.table_of_contents_offset = toc_offset;
        let toc_offset_size: u32 = 4;
        let (input, core_data) = take(book_data.table_of_contents_offset - toc_offset_size)(input)?;

        let (input, toc_header) = LoginItemsData::table_of_contents_header(input)?;

        let (toc_record_data, toc_content_data) =
            LoginItemsData::table_of_contents_data(input, toc_header.data_length)?;

        let (_, toc_content_data_record) = LoginItemsData::table_of_contents_record(
            toc_record_data,
            &toc_content_data.number_of_records,
        )?;

        let mut login_items_data = LoginItemsData {
            path: Vec::new(),
            cnid_path: Vec::new(),
            target_flags: Vec::new(),
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
            username: String::new(),
            uid: 0,
            creation_options: 0,
            folder_index: 0,
            is_bundled: false,
            app_id: String::new(),
            app_binary: String::new(),
        };

        for record in toc_content_data_record {
            let (_, standard_data) = LoginItemsData::bookmark_standard_data(core_data, &record)?;
            let record_data = standard_data.record_data;
            let mut standard_data_vec: Vec<StandardDataRecord> = Vec::new();

            // If data type is ARRAY, standard_data data points to offsets that contain actual loginitem data
            if standard_data.data_type == LoginItemsData::ARRAY_TYPE {
                let results_data = LoginItemsData::bookmark_array(&record_data);
                match results_data {
                    Ok((_, results)) => {
                        if results.is_empty() {
                            continue;
                        }

                        let (_, std_data_vec) =
                            LoginItemsData::loginitem_data(core_data, results, &record)?;

                        // Now we have data for actual loginitem data
                        standard_data_vec = std_data_vec;
                    }
                    Err(err) => warn!("Failed to get bookmark standard data: {:?}", err),
                }
            }

            // If we did not have to parse array data, get loginitem data based on record and data types
            if standard_data_vec.is_empty() {
                if standard_data.record_type == LoginItemsData::TARGET_FLAGS
                    && standard_data.data_type == LoginItemsData::DATA_TYPE
                {
                    let flag_data = LoginItemsData::bookmark_target_flags(&record_data);
                    match flag_data {
                        Ok((_, flags)) => {
                            if flags.is_empty() {
                                continue;
                            }
                            login_items_data.target_flags = flags;
                        }
                        Err(err) => warn!("Failed to parse Target Flags: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::TARGET_CREATION_DATE
                    && standard_data.data_type == LoginItemsData::DATE
                {
                    let creation_data = LoginItemsData::bookmark_data_type_date(&record_data);
                    match creation_data {
                        Ok((_, creation)) => login_items_data.creation = creation,
                        Err(err) => warn!("Failed to parse Target creation timestamp: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::VOLUME_PATH
                    && standard_data.data_type == LoginItemsData::STRING_TYPE
                {
                    let volume_root = LoginItemsData::bookmark_data_type_string(&record_data);
                    match volume_root {
                        Ok(volume_root_data) => login_items_data.volume_path = volume_root_data,
                        Err(err) => warn!("Failed to parse Volume Path: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::VOLUME_URL
                    && standard_data.data_type == LoginItemsData::URL
                {
                    let volume_url_data = LoginItemsData::bookmark_data_type_string(&record_data);
                    match volume_url_data {
                        Ok(volume_url) => login_items_data.volume_url = volume_url,
                        Err(err) => warn!("Failed to parse Volume URL data: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::VOLUME_NAME
                    && standard_data.data_type == LoginItemsData::STRING_TYPE
                {
                    let volume_name_data = LoginItemsData::bookmark_data_type_string(&record_data);
                    match volume_name_data {
                        Ok(volume_name) => login_items_data.volume_name = volume_name,
                        Err(err) => warn!("Failed to parse Volume Name data: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::VOLUME_UUID
                    && standard_data.data_type == LoginItemsData::STRING_TYPE
                {
                    let volume_uuid_data = LoginItemsData::bookmark_data_type_string(&record_data);
                    match volume_uuid_data {
                        Ok(volume_uuid) => login_items_data.volume_uuid = volume_uuid,
                        Err(err) => warn!("Failed to parse Volume UUID: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::VOLUME_SIZE
                    && standard_data.data_type == LoginItemsData::NUMBER_EIGHT_BYTE
                {
                    let test = LoginItemsData::bookmark_data_type_number_eight(&record_data);
                    match test {
                        Ok((_, size)) => login_items_data.volume_size = size,
                        Err(err) => warn!("Failed to parse Volume size: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::VOLUME_CREATION
                    && standard_data.data_type == LoginItemsData::DATE
                {
                    let creation_data = LoginItemsData::bookmark_data_type_date(&record_data);
                    match creation_data {
                        Ok((_, creation)) => login_items_data.volume_creation = creation,
                        Err(err) => warn!("Failed to parse Volume Creation timestamp: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::VOLUME_FLAGS
                    && standard_data.data_type == LoginItemsData::DATA_TYPE
                {
                    let flags_data = LoginItemsData::bookmark_target_flags(&record_data);
                    match flags_data {
                        Ok((_, flags)) => login_items_data.volume_flag = flags,
                        Err(err) => warn!("Failed to parse Volume Flags: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::VOLUME_ROOT
                    && standard_data.data_type == LoginItemsData::BOOL_TRUE
                {
                    login_items_data.volume_root = true;
                } else if standard_data.record_type == LoginItemsData::LOCALIZED_NAME
                    && standard_data.data_type == LoginItemsData::STRING_TYPE
                {
                    let local_name_data = LoginItemsData::bookmark_data_type_string(&record_data);
                    match local_name_data {
                        Ok(local_name) => login_items_data.localized_name = local_name,
                        Err(err) => warn!("Failed to parse Localized Name: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::SECURITY_EXTENSION
                    && standard_data.data_type == LoginItemsData::DATA_TYPE
                {
                    let extension_data = LoginItemsData::bookmark_data_type_string(&record_data);
                    match extension_data {
                        Ok(extension) => login_items_data.security_extension = extension,
                        Err(err) => warn!("Failed to parse Security Extension: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::CREATOR_USERNAME
                    && standard_data.data_type == LoginItemsData::STRING_TYPE
                {
                    let username_data = LoginItemsData::bookmark_data_type_string(&record_data);
                    match username_data {
                        Ok(username) => login_items_data.username = username,
                        Err(err) => warn!("Failed to parse bookmark username: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::CONTAIN_FOLDER_INDEX
                    && standard_data.data_type == LoginItemsData::NUMBER_FOUR_BYTE
                {
                    let index_data = LoginItemsData::bookmark_data_type_number_four(&record_data);
                    match index_data {
                        Ok((_, index)) => login_items_data.folder_index = index,
                        Err(err) => warn!("Failed to parse bookmark folder index: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::CREATOR_UID
                    && standard_data.data_type == LoginItemsData::NUMBER_FOUR_BYTE
                {
                    let uid_data = LoginItemsData::bookmark_data_type_number_four(&record_data);
                    match uid_data {
                        Ok((_, uid)) => login_items_data.uid = uid,
                        Err(err) => warn!("Failed to parse bookmark Creator UID: {:?}", err),
                    }
                } else if standard_data.record_type == LoginItemsData::CREATION_OPTIONS
                    && standard_data.data_type == LoginItemsData::NUMBER_FOUR_BYTE
                {
                    let creation_options_data =
                        LoginItemsData::bookmark_data_type_number_four(&record_data);
                    match creation_options_data {
                        Ok((_, options)) => login_items_data.creation_options = options,
                        Err(err) => warn!("Failed to parse bookmark Creation options: {:?}", err),
                    }
                }
                continue;
            }

            // Get loginitem array data based on data and record types
            for standard_data in standard_data_vec {
                if standard_data.data_type == LoginItemsData::STRING_TYPE
                    && standard_data.record_type == LoginItemsData::TARGET_PATH
                {
                    let path_data =
                        LoginItemsData::bookmark_data_type_string(&standard_data.record_data);
                    match path_data {
                        Ok(path) => login_items_data.path.push(path),
                        Err(_err) => continue,
                    }
                } else if standard_data.data_type == LoginItemsData::NUMBER_EIGHT_BYTE
                    && standard_data.record_type == LoginItemsData::TARGET_CNID_PATH
                {
                    let cnid_data = LoginItemsData::bookmark_cnid(&standard_data.record_data);
                    match cnid_data {
                        Ok((_, cnid)) => login_items_data.cnid_path.push(cnid),
                        Err(_err) => continue,
                    }
                }
            }
        }
        Ok((input, login_items_data))
    }

    /// Parse the Table of Contents (TOC) header
    fn table_of_contents_header(data: &[u8]) -> nom::IResult<&[u8], TableOfContentsHeader> {
        let mut toc_header = TableOfContentsHeader {
            data_length: 0,
            record_type: 0,
            flags: 0,
        };

        let (input, length) = take(size_of::<u32>())(data)?;
        let (input, record_type) = take(size_of::<u16>())(input)?;
        let (input, flags) = take(size_of::<u16>())(input)?;

        let (_, toc_length) = le_u32(length)?;
        let (_, toc_record_type) = le_u16(record_type)?;
        let (_, toc_flags) = le_u16(flags)?;

        toc_header.data_length = toc_length;
        toc_header.record_type = toc_record_type;
        toc_header.flags = toc_flags;

        Ok((input, toc_header))
    }

    /// Parse the TOC data
    fn table_of_contents_data(
        data: &[u8],
        data_length: u32,
    ) -> nom::IResult<&[u8], TableOfContentsData> {
        let mut toc_data = TableOfContentsData {
            level: 0,
            next_record_offset: 0,
            number_of_records: 0,
        };

        let (input, level) = take(size_of::<u32>())(data)?;
        let (input, next_record_offset) = take(size_of::<u32>())(input)?;
        let (input, number_of_records) = take(size_of::<u32>())(input)?;

        let mut final_input = input;

        let (_, toc_level) = le_u32(level)?;
        let (_, toc_next_record) = le_u32(next_record_offset)?;
        let (_, toc_number_records) = le_u32(number_of_records)?;

        toc_data.level = toc_level;
        toc_data.next_record_offset = toc_next_record;
        toc_data.number_of_records = toc_number_records;

        let record_size = 12;
        let record_data = record_size * toc_data.number_of_records;

        // Verify TOC data length is equal to number of records (Number of Records * Record Size (12 bytes))
        // Some TOC headers may give incorrect? data length (they are 8 bytes short, https://mac-alias.readthedocs.io/en/latest/bookmark_fmt.html)
        if record_data > data_length {
            let (_, actual_record_data) = take(record_data)(input)?;
            final_input = actual_record_data;
        }
        Ok((final_input, toc_data))
    }

    /// Parse the TOC data record
    fn table_of_contents_record<'a>(
        data: &'a [u8],
        records: &u32,
    ) -> nom::IResult<&'a [u8], Vec<TableOfContentsDataRecord>> {
        let mut input_data = data;
        let mut record: u32 = 0;
        let mut toc_records_vec: Vec<TableOfContentsDataRecord> = Vec::new();

        // Loop through until all records have been parsed
        loop {
            if &record == records {
                break;
            }
            record += 1;
            let mut toc_data_record = TableOfContentsDataRecord {
                record_type: 0,
                data_offset: 0,
                reserved: 0,
            };

            let (input, record_type) = take(size_of::<u32>())(input_data)?;
            let (input, offset) = take(size_of::<u32>())(input)?;
            let (input, reserved) = take(size_of::<u32>())(input)?;
            input_data = input;

            let (_, toc_record) = le_u32(record_type)?;
            let (_, toc_offset) = le_u32(offset)?;
            let (_, toc_reserved) = le_u32(reserved)?;

            toc_data_record.record_type = toc_record;
            toc_data_record.data_offset = toc_offset;
            toc_data_record.reserved = toc_reserved;
            toc_records_vec.push(toc_data_record);
        }
        Ok((input_data, toc_records_vec))
    }

    /// Parse the bookmark standard data
    fn bookmark_standard_data<'a>(
        bookmark_data: &'a [u8],
        toc_record: &TableOfContentsDataRecord,
    ) -> nom::IResult<&'a [u8], StandardDataRecord> {
        let mut toc_standard_data = StandardDataRecord {
            data_length: 0,
            record_data: Vec::new(),
            data_type: 0,
            record_type: 0,
        };
        let toc_offset_value: u32 = 4;

        // Subtract toc offset value from data offset since we already nom'd the value
        let offset = (toc_record.data_offset - toc_offset_value) as usize;

        // Nom data til standard data info
        let (input, _) = take(offset)(bookmark_data)?;

        let (input, length) = take(size_of::<u32>())(input)?;
        let (input, data_type) = take(size_of::<u32>())(input)?;

        let (_, standard_length) = le_u32(length)?;
        let (_, standard_data_type) = le_u32(data_type)?;

        let (input, record_data) = take(standard_length)(input)?;

        toc_standard_data.data_length = standard_length;
        toc_standard_data.data_type = standard_data_type;
        toc_standard_data.record_data = record_data.to_vec();
        toc_standard_data.record_type = toc_record.record_type;

        Ok((input, toc_standard_data))
    }

    /// Parse the bookmark array data
    fn loginitem_data<'a>(
        data: &'a [u8],
        array_offsets: Vec<u32>,
        record: &TableOfContentsDataRecord,
    ) -> nom::IResult<&'a [u8], Vec<StandardDataRecord>> {
        let mut standard_data_vec: Vec<StandardDataRecord> = Vec::new();

        for offset in array_offsets {
            let data_record = TableOfContentsDataRecord {
                record_type: record.record_type,
                data_offset: offset,
                reserved: 0,
            };
            let (_, results) = LoginItemsData::bookmark_standard_data(data, &data_record)?;
            standard_data_vec.push(results);
        }

        Ok((data, standard_data_vec))
    }

    /// Get the offsets for the array data
    fn bookmark_array(standard_data: &[u8]) -> nom::IResult<&[u8], Vec<u32>> {
        let mut array_offsets: Vec<u32> = Vec::new();
        let mut input = standard_data;
        let offset_size: u32 = 4;

        loop {
            let (input_data, offset) = take(offset_size)(input)?;
            let (_, data_offsets) = le_u32(offset)?;

            array_offsets.push(data_offsets);
            input = input_data;
            if input_data.is_empty() {
                break;
            }
        }
        Ok((input, array_offsets))
    }

    /// Get the path/strings related to bookmark
    fn bookmark_data_type_string(standard_data: &[u8]) -> Result<String, Utf8Error> {
        let path = from_utf8(standard_data)?;
        Ok(path.to_string())
    }

    /// Get the CNID path for the target
    fn bookmark_cnid(standard_data: &[u8]) -> nom::IResult<&[u8], i64> {
        let (data, cnid) = le_i64(standard_data)?;
        Ok((data, cnid))
    }

    /// Get bookmark target flags
    fn bookmark_target_flags(standard_data: &[u8]) -> nom::IResult<&[u8], Vec<u64>> {
        let mut input = standard_data;
        let mut array_flags: Vec<u64> = Vec::new();
        let max_flag_size = 3;

        // Target flags are composed of three (3) 8 byte values
        loop {
            let (data, flag) = take(size_of::<u64>())(input)?;
            input = data;
            let (_, flags) = le_u64(flag)?;
            array_flags.push(flags);
            if input.is_empty() || array_flags.len() == max_flag_size {
                break;
            }
        }
        Ok((input, array_flags))
    }

    /// Get bookmark volume size
    fn bookmark_data_type_number_eight(standard_data: &[u8]) -> nom::IResult<&[u8], i64> {
        let (data, size) = le_i64(standard_data)?;
        Ok((data, size))
    }

    /// Get bookmark folder index
    fn bookmark_data_type_number_four(standard_data: &[u8]) -> nom::IResult<&[u8], i32> {
        let (data, index) = le_i32(standard_data)?;
        Ok((data, index))
    }

    /// Get bookmark creation timestamps
    fn bookmark_data_type_date(standard_data: &[u8]) -> nom::IResult<&[u8], f64> {
        //Apple stores timestamps as Big Endian Float64
        let (data, creation) = be_f64(standard_data)?;
        Ok((data, creation))
    }

    /// Get loginitem data from embedded loginitems in Apps
    pub fn loginitem_apps() -> Result<Vec<LoginItemsResults>, std::io::Error> {
        const BUNDLED_APP_LOGINITEMS_PATH: &str = "/var/db/com.apple.xpc.launchd/";
        let mut loginitems_vec: Vec<LoginItemsResults> = Vec::new();
        for dir in read_dir(BUNDLED_APP_LOGINITEMS_PATH)? {
            let mut loginitems = LoginItemsResults {
                results: Vec::new(),
                path: String::new(),
            };
            let entry = dir?;

            let path = format!("{}", entry.path().display());
            let full_path = Path::new(&path);

            if !full_path.display().to_string().contains("loginitems") {
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
                        };
                        if key.starts_with("version") {
                            continue;
                        }
                        loginitems_data.app_id = value.as_string().unwrap().to_string();
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
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use super::{LoginItemsData, TableOfContentsDataRecord};

    #[test]
    fn test_loginitem_apps() {
        let results = LoginItemsData::loginitem_apps().unwrap();
        assert!(results.len() > 0)
    }

    #[test]
    fn test_parse_loginitems() {
        let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_location.push("tests/test_data/backgrounditems_sierra.btm");
        let loginitems_data =
            LoginItemsData::parse_loginitems(&test_location.display().to_string()).unwrap();

        let app_path = ["Applications", "Syncthing.app"];
        let cnid_path = [103, 706090];
        let security_extension = "64cb7eaa9a1bbccc4e1397c9f2a411ebe539cd29;00000000;00000000;0000000000000020;com.apple.app-sandbox.read-write;01;01000004;00000000000ac62a;/applications/syncthing.app\u{0}";
        assert!(loginitems_data.results[0].path == app_path);
        assert!(loginitems_data.results[0].cnid_path == cnid_path);
        assert!(loginitems_data.results[0].security_extension == security_extension);
    }

    #[test]
    fn test_bookmark_header() {
        let test_header = [
            98, 111, 111, 107, 72, 2, 0, 0, 0, 0, 4, 16, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (_, header) = LoginItemsData::bookmark_header(test_header.as_slice()).unwrap();
        let book_sig: u32 = 1802465122;
        let book_length: u32 = 584;
        let book_offset: u32 = 48;
        let book_version: u32 = 1040;
        assert!(header.signature == book_sig);
        assert!(header.bookmark_data_length == book_length);
        assert!(header.bookmark_data_offset == book_offset);
        assert!(header.version == book_version);
    }

    #[test]
    fn test_table_of_contents_header() {
        let test_header = [192, 0, 0, 0, 254, 255, 255, 255];
        let (_, header) = LoginItemsData::table_of_contents_header(test_header.as_slice()).unwrap();
        let toc_length: u32 = 192;
        let toc_record_type: u16 = 65534;
        let toc_flags: u16 = 65535;
        assert!(header.data_length == toc_length);
        assert!(header.record_type == toc_record_type);
        assert!(header.flags == toc_flags);
    }

    #[test]
    fn test_bookmark_data() {
        let test_data = [
            8, 2, 0, 0, 12, 0, 0, 0, 1, 1, 0, 0, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111,
            110, 115, 13, 0, 0, 0, 1, 1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 46, 97,
            112, 112, 0, 0, 0, 8, 0, 0, 0, 1, 6, 0, 0, 4, 0, 0, 0, 24, 0, 0, 0, 8, 0, 0, 0, 4, 3,
            0, 0, 103, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 42, 198, 10, 0, 0, 0, 0, 0, 8,
            0, 0, 0, 1, 6, 0, 0, 64, 0, 0, 0, 80, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 195, 213,
            41, 226, 128, 0, 0, 24, 0, 0, 0, 1, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1, 9, 0, 0, 102, 105, 108, 101, 58, 47, 47,
            47, 12, 0, 0, 0, 1, 1, 0, 0, 77, 97, 99, 105, 110, 116, 111, 115, 104, 32, 72, 68, 8,
            0, 0, 0, 4, 3, 0, 0, 0, 96, 127, 115, 37, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 172,
            190, 215, 104, 0, 0, 0, 36, 0, 0, 0, 1, 1, 0, 0, 48, 65, 56, 49, 70, 51, 66, 49, 45,
            53, 49, 68, 57, 45, 51, 51, 51, 53, 45, 66, 51, 69, 51, 45, 49, 54, 57, 67, 51, 54, 52,
            48, 51, 54, 48, 68, 24, 0, 0, 0, 1, 2, 0, 0, 129, 0, 0, 0, 1, 0, 0, 0, 239, 19, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 47, 0, 0, 0, 0, 0, 0, 0, 1,
            5, 0, 0, 9, 0, 0, 0, 1, 1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 0, 0, 0,
            166, 0, 0, 0, 1, 2, 0, 0, 54, 52, 99, 98, 55, 101, 97, 97, 57, 97, 49, 98, 98, 99, 99,
            99, 52, 101, 49, 51, 57, 55, 99, 57, 102, 50, 97, 52, 49, 49, 101, 98, 101, 53, 51, 57,
            99, 100, 50, 57, 59, 48, 48, 48, 48, 48, 48, 48, 48, 59, 48, 48, 48, 48, 48, 48, 48,
            48, 59, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 48, 59, 99, 111,
            109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 45, 115, 97, 110, 100, 98, 111, 120,
            46, 114, 101, 97, 100, 45, 119, 114, 105, 116, 101, 59, 48, 49, 59, 48, 49, 48, 48, 48,
            48, 48, 52, 59, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 97, 99, 54, 50, 97, 59, 47,
            97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 115, 47, 115, 121, 110, 99, 116,
            104, 105, 110, 103, 46, 97, 112, 112, 0, 0, 0, 180, 0, 0, 0, 254, 255, 255, 255, 1, 0,
            0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 4, 16, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 5, 16, 0, 0, 96,
            0, 0, 0, 0, 0, 0, 0, 16, 16, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 64, 16, 0, 0, 112, 0, 0,
            0, 0, 0, 0, 0, 2, 32, 0, 0, 48, 1, 0, 0, 0, 0, 0, 0, 5, 32, 0, 0, 160, 0, 0, 0, 0, 0,
            0, 0, 16, 32, 0, 0, 176, 0, 0, 0, 0, 0, 0, 0, 17, 32, 0, 0, 228, 0, 0, 0, 0, 0, 0, 0,
            18, 32, 0, 0, 196, 0, 0, 0, 0, 0, 0, 0, 19, 32, 0, 0, 212, 0, 0, 0, 0, 0, 0, 0, 32, 32,
            0, 0, 16, 1, 0, 0, 0, 0, 0, 0, 48, 32, 0, 0, 60, 1, 0, 0, 0, 0, 0, 0, 23, 240, 0, 0,
            68, 1, 0, 0, 0, 0, 0, 0, 128, 240, 0, 0, 88, 1, 0, 0, 0, 0, 0, 0,
        ];
        let (_, loginitem) = LoginItemsData::bookmark_data(test_data.as_slice()).unwrap();
        let app_path_len = 2;
        let cnid_path_len = 2;
        let target_creation = 665473989.0;
        let volume_creation = 241134516.0;
        let target_flags_len = 3;

        assert!(loginitem.path.len() == app_path_len);
        assert!(loginitem.cnid_path.len() == cnid_path_len);
        assert!(loginitem.creation == target_creation);
        assert!(loginitem.volume_creation == volume_creation);
        assert!(loginitem.target_flags.len() == target_flags_len);
    }

    #[test]
    fn test_table_of_contents_data() {
        let test_data = [
            1, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 4, 16, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 5, 16, 0, 0,
        ];
        let record_data_size = 192;
        let (_, toc_data) =
            LoginItemsData::table_of_contents_data(test_data.as_slice(), record_data_size).unwrap();
        let level = 1;
        let next_record_offset = 0;
        let number_of_records = 15;
        assert!(toc_data.level == level);
        assert!(toc_data.next_record_offset == next_record_offset);
        assert!(toc_data.number_of_records == number_of_records);
    }

    #[test]
    fn test_table_of_contents_record() {
        let test_record = [
            4, 16, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 5, 16, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 16, 16, 0,
            0, 128, 0, 0, 0, 0, 0, 0, 0, 64, 16, 0, 0, 112, 0, 0, 0, 0, 0, 0, 0, 2, 32, 0, 0, 48,
            1, 0, 0, 0, 0, 0, 0, 5, 32, 0, 0, 160, 0, 0, 0, 0, 0, 0, 0, 16, 32, 0, 0, 176, 0, 0, 0,
            0, 0, 0, 0, 17, 32, 0, 0, 228, 0, 0, 0, 0, 0, 0, 0, 18, 32, 0, 0, 196, 0, 0, 0, 0, 0,
            0, 0, 19, 32, 0, 0, 212, 0, 0, 0, 0, 0, 0, 0, 32, 32, 0, 0, 16, 1, 0, 0, 0, 0, 0, 0,
            48, 32, 0, 0, 60, 1, 0, 0, 0, 0, 0, 0, 23, 240, 0, 0, 68, 1, 0, 0, 0, 0, 0, 0, 128,
            240, 0, 0, 88, 1, 0, 0, 0, 0, 0, 0,
        ];
        let records = 14;

        let (_, record) =
            LoginItemsData::table_of_contents_record(test_record.as_slice(), &records).unwrap();
        let record_type = 4100;
        let record_offset = 48;
        let record_reserved = 0;

        assert!(record[0].record_type == record_type);
        assert!(record[0].data_offset == record_offset);
        assert!(record[0].reserved == record_reserved);
        assert!(record.len() == records.try_into().unwrap());
    }

    #[test]
    fn test_bookmark_standard_data() {
        let bookmark_data = [
            12, 0, 0, 0, 1, 1, 0, 0, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 115, 13,
            0, 0, 0, 1, 1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 46, 97, 112, 112, 0, 0,
            0, 8, 0, 0, 0, 1, 6, 0, 0, 4, 0, 0, 0, 24, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 103, 0, 0,
            0, 0, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 42, 198, 10, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1, 6, 0,
            0, 64, 0, 0, 0, 80, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 195, 213, 41, 226, 128, 0, 0,
            24, 0, 0, 0, 1, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 8, 0, 0, 0, 1, 9, 0, 0, 102, 105, 108, 101, 58, 47, 47, 47, 12, 0, 0, 0, 1,
            1, 0, 0, 77, 97, 99, 105, 110, 116, 111, 115, 104, 32, 72, 68, 8, 0, 0, 0, 4, 3, 0, 0,
            0, 96, 127, 115, 37, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 172, 190, 215, 104, 0, 0, 0,
            36, 0, 0, 0, 1, 1, 0, 0, 48, 65, 56, 49, 70, 51, 66, 49, 45, 53, 49, 68, 57, 45, 51,
            51, 51, 53, 45, 66, 51, 69, 51, 45, 49, 54, 57, 67, 51, 54, 52, 48, 51, 54, 48, 68, 24,
            0, 0, 0, 1, 2, 0, 0, 129, 0, 0, 0, 1, 0, 0, 0, 239, 19, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 47, 0, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 9, 0, 0, 0, 1,
            1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 0, 0, 0, 166, 0, 0, 0, 1, 2, 0, 0,
            54, 52, 99, 98, 55, 101, 97, 97, 57, 97, 49, 98, 98, 99, 99, 99, 52, 101, 49, 51, 57,
            55, 99, 57, 102, 50, 97, 52, 49, 49, 101, 98, 101, 53, 51, 57, 99, 100, 50, 57, 59, 48,
            48, 48, 48, 48, 48, 48, 48, 59, 48, 48, 48, 48, 48, 48, 48, 48, 59, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 48, 59, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 97, 112, 112, 45, 115, 97, 110, 100, 98, 111, 120, 46, 114, 101, 97, 100, 45,
            119, 114, 105, 116, 101, 59, 48, 49, 59, 48, 49, 48, 48, 48, 48, 48, 52, 59, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 97, 99, 54, 50, 97, 59, 47, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 115, 47, 115, 121, 110, 99, 116, 104, 105, 110, 103, 46,
            97, 112, 112, 0, 0, 0,
        ];
        let toc_record = TableOfContentsDataRecord {
            record_type: 8209,
            data_offset: 228,
            reserved: 0,
        };
        let (_, std_data) =
            LoginItemsData::bookmark_standard_data(bookmark_data.as_slice(), &toc_record).unwrap();

        let data_length = 36;
        let data_type = 257;
        let record_data = [
            48, 65, 56, 49, 70, 51, 66, 49, 45, 53, 49, 68, 57, 45, 51, 51, 51, 53, 45, 66, 51, 69,
            51, 45, 49, 54, 57, 67, 51, 54, 52, 48, 51, 54, 48, 68,
        ];
        let record_type = 8209;

        assert!(std_data.data_length == data_length);
        assert!(std_data.data_type == data_type);
        assert!(std_data.record_data == record_data);
        assert!(std_data.record_type == record_type);
    }

    #[test]
    fn test_loginitem_data() {
        let test_data = [
            12, 0, 0, 0, 1, 1, 0, 0, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 115, 13,
            0, 0, 0, 1, 1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 46, 97, 112, 112, 0, 0,
            0, 8, 0, 0, 0, 1, 6, 0, 0, 4, 0, 0, 0, 24, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 103, 0, 0,
            0, 0, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 42, 198, 10, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1, 6, 0,
            0, 64, 0, 0, 0, 80, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 195, 213, 41, 226, 128, 0, 0,
            24, 0, 0, 0, 1, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 8, 0, 0, 0, 1, 9, 0, 0, 102, 105, 108, 101, 58, 47, 47, 47, 12, 0, 0, 0, 1,
            1, 0, 0, 77, 97, 99, 105, 110, 116, 111, 115, 104, 32, 72, 68, 8, 0, 0, 0, 4, 3, 0, 0,
            0, 96, 127, 115, 37, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 172, 190, 215, 104, 0, 0, 0,
            36, 0, 0, 0, 1, 1, 0, 0, 48, 65, 56, 49, 70, 51, 66, 49, 45, 53, 49, 68, 57, 45, 51,
            51, 51, 53, 45, 66, 51, 69, 51, 45, 49, 54, 57, 67, 51, 54, 52, 48, 51, 54, 48, 68, 24,
            0, 0, 0, 1, 2, 0, 0, 129, 0, 0, 0, 1, 0, 0, 0, 239, 19, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 47, 0, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 9, 0, 0, 0, 1,
            1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 0, 0, 0, 166, 0, 0, 0, 1, 2, 0, 0,
            54, 52, 99, 98, 55, 101, 97, 97, 57, 97, 49, 98, 98, 99, 99, 99, 52, 101, 49, 51, 57,
            55, 99, 57, 102, 50, 97, 52, 49, 49, 101, 98, 101, 53, 51, 57, 99, 100, 50, 57, 59, 48,
            48, 48, 48, 48, 48, 48, 48, 59, 48, 48, 48, 48, 48, 48, 48, 48, 59, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 48, 59, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 97, 112, 112, 45, 115, 97, 110, 100, 98, 111, 120, 46, 114, 101, 97, 100, 45,
            119, 114, 105, 116, 101, 59, 48, 49, 59, 48, 49, 48, 48, 48, 48, 48, 52, 59, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 97, 99, 54, 50, 97, 59, 47, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 115, 47, 115, 121, 110, 99, 116, 104, 105, 110, 103, 46,
            97, 112, 112, 0, 0, 0,
        ];
        let test_array_offsets = [4, 24];
        let toc_record = TableOfContentsDataRecord {
            record_type: 4100,
            data_offset: 48,
            reserved: 0,
        };
        let records = 2;

        let (_, std_record) = LoginItemsData::loginitem_data(
            test_data.as_slice(),
            (&test_array_offsets).to_vec(),
            &toc_record,
        )
        .unwrap();
        let record_type = 4100;
        let data_type = 257;
        let record_data = [65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 115];
        let data_length = 12;

        assert!(std_record[0].record_type == record_type);
        assert!(std_record[0].data_type == data_type);
        assert!(std_record[0].record_data == record_data);
        assert!(std_record[0].data_length == data_length);

        assert!(std_record.len() == records.try_into().unwrap());
    }

    #[test]
    fn test_bookmark_array() {
        let test_array = [4, 0, 0, 0, 24, 0, 0, 0];

        let (_, book_array) = LoginItemsData::bookmark_array(test_array.as_slice()).unwrap();
        let offset = 4;
        let offset_2 = 24;

        let offsets = 2;
        assert!(book_array.len() == offsets);

        assert!(book_array[0] == offset);
        assert!(book_array[1] == offset_2);
    }

    #[test]
    fn test_bookmark_data_type_string() {
        let test_path = [83, 121, 110, 99, 116, 104, 105, 110, 103];

        let book_path = LoginItemsData::bookmark_data_type_string(test_path.as_slice()).unwrap();
        let path = "Syncthing";
        assert!(book_path == path);
    }

    #[test]
    fn test_bookmark_cnid() {
        let test_cnid = [42, 198, 10, 0, 0, 0, 0, 0];

        let (_, book_cnid) = LoginItemsData::bookmark_cnid(test_cnid.as_slice()).unwrap();
        let cnid = 706090;
        assert!(book_cnid == cnid);
    }

    #[test]
    fn test_bookmark_target_flags() {
        let test_flags = [
            129, 0, 0, 0, 1, 0, 0, 0, 239, 19, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let (_, book_flags) = LoginItemsData::bookmark_target_flags(test_flags.as_slice()).unwrap();
        let flag = 4294967425;
        let flag_2 = 4294972399;
        let flag_3 = 0;

        let flags = 3;

        assert!(book_flags.len() == flags);
        assert!(book_flags[0] == flag);
        assert!(book_flags[1] == flag_2);
        assert!(book_flags[2] == flag_3);
    }

    #[test]
    fn test_bookmark_data_type_number_eight() {
        let test_volume_size = [0, 96, 127, 115, 37, 0, 0, 0];

        let (_, book_size) =
            LoginItemsData::bookmark_data_type_number_eight(test_volume_size.as_slice()).unwrap();
        let size = 160851517440;

        assert!(book_size == size);
    }

    #[test]
    fn test_bookmark_data_type_date() {
        let test_creation = [65, 172, 190, 215, 104, 0, 0, 0];

        let (_, book_creation) =
            LoginItemsData::bookmark_data_type_date(test_creation.as_slice()).unwrap();
        let creation = 241134516.0;

        assert!(book_creation == creation);
    }

    #[test]
    fn test_bookmark_data_type_number_four() {
        let test_creation = [0, 0, 0, 32];

        let (_, creation_options) =
            LoginItemsData::bookmark_data_type_number_four(test_creation.as_slice()).unwrap();
        let options = 536870912;
        assert!(creation_options == options);
    }
}
