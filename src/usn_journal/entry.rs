use crate::attribute::FileAttributeFlags;
use crate::err::Error;
use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Utc};
use encoding::all::UTF_16LE;
use encoding::{DecoderTrap, Encoding};
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use winstructs::timestamp::WinTimestamp;

bitflags! {
    /// Flag sources:
    /// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d2a2b53e-bf78-4ef3-90c7-21b918fab304>
    ///
    pub struct UsnReasonFlags: u32 {
        const USN_REASON_BASIC_INFO_CHANGE          = 0x00008000;
        const USN_REASON_CLOSE                      = 0x80000000;
        const USN_REASON_COMPRESSION_CHANGE         = 0x00020000;
        const USN_REASON_DATA_EXTEND                = 0x00000002;
        const USN_REASON_DATA_OVERWRITE             = 0x00000001;
        const USN_REASON_DATA_TRUNCATION            = 0x00000004;
        const USN_REASON_EA_CHANGE                  = 0x00000400;
        const USN_REASON_ENCRYPTION_CHANGE          = 0x00040000;
        const USN_REASON_FILE_CREATE                = 0x00000100;
        const USN_REASON_FILE_DELETE                = 0x00000200;
        const USN_REASON_HARD_LINK_CHANGE           = 0x00010000;
        const USN_REASON_INDEXABLE_CHANGE           = 0x00004000;
        const USN_REASON_NAMED_DATA_EXTEND          = 0x00000020;
        const USN_REASON_NAMED_DATA_OVERWRITE       = 0x00000010;
        const USN_REASON_NAMED_DATA_TRUNCATION      = 0x00000040;
        const USN_REASON_OBJECT_ID_CHANGE           = 0x00080000;
        const USN_REASON_RENAME_NEW_NAME            = 0x00002000;
        const USN_REASON_RENAME_OLD_NAME            = 0x00001000;
        const USN_REASON_REPARSE_POINT_CHANGE       = 0x00100000;
        const USN_REASON_SECURITY_CHANGE            = 0x00000800;
        const USN_REASON_STREAM_CHANGE              = 0x00200000;
        const USN_REASON_INTEGRITY_CHANGE           = 0x00800000;
    }
}

impl UsnReasonFlags {
    pub fn get_meaning(&self) -> &str {
        match self.bits {
            0x00008000 => {
                "A user has either changed one or more files or directory attributes 
                (such as read-only, hidden, archive, or sparse) or one or more time stamps."
            }
            0x80000000 => "The file or directory is closed.",
            0x00020000 => {
                "The compression state of the file or directory is changed from (or to) compressed."
            }
            0x00000002 => "The file or directory is extended (added to).",
            0x00000001 => "The data in the file or directory is overwritten.",
            0x00000004 => "The file or directory is truncated.",
            0x00000400 => {
                "The user made a change to the extended 
                attributes of a file or directory. These NTFS file system attributes are not
                accessible to nonnative applications. This USN reason does not appear under normal
                system usage but can appear if an application or utility bypasses the Win32 API and
                uses the native API to create or modify extended attributes of a file or directory."
            }
            0x00040000 => "The file or directory is encrypted or decrypted.",
            0x00000100 => "The file or directory is created for the first time.",
            0x00000200 => "The file or directory is deleted.",
            0x00010000 => "A hard link is added to (or removed from) the file or directory.",
            0x00004000 => {
                "A user changes the FILE_ATTRIBUTE_NOT_CONTEXT_INDEXED attribute. That is, the
                user changes the file or directory from one in which content can be indexed to
                one in which content cannot be indexed, or vice versa."
            }
            0x00000020 => "The one (or more) named data stream for a file is extended (added to).",
            0x00000010 => "The data in one (or more) named data stream for a file is overwritten.",
            0x00000040 => "One (or more) named data stream for a file is truncated.",
            0x00080000 => "The object identifier of a file or directory is changed.",
            0x00002000 => {
                "A file or directory is renamed, and the file name in the USN_RECORD structure
                is the new name."
            }
            0x00001000 => {
                "The file or directory is renamed, and the file name in the USN_RECORD structure
                is the previous name."
            }
            0x00100000 => {
                "The reparse point that is contained in a file or directory is changed, or a
                reparse point is added to (or deleted from) a file or directory."
            }
            0x00000800 => "A change is made in the access rights to a file or directory.",
            0x00200000 => {
                "A named stream is added to (or removed from) a file, or a named stream is renamed."
            }
            0x00800000 => "A change is made in the integrity status of a file or directory.",
            _ => "",
        }
    }
}

bitflags! {
    /// Flag sources:
    /// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d2a2b53e-bf78-4ef3-90c7-21b918fab304>
    ///
    pub struct UsnSourceInfoFlags: u32 {
        const USN_SOURCE_DATA_MANAGEMENT            = 0x00000001;
        const USN_SOURCE_AUXILIARY_DATA             = 0x00000002;
        const USN_SOURCE_REPLICATION_MANAGEMENT     = 0x00000004;
    }
}

impl UsnSourceInfoFlags {
    pub fn get_meaning(&self) -> &str {
        match self.bits {
            0x00000001 => {
                "The operation provides information about a change to 
                the file or directory that was made by the operating system. For example, a change
                journal record with this SourceInfo value is generated when the Remote Storage
                system moves data from external to local storage. This SourceInfo value indicates
                that the modifications did not change the application data in the file."
            }
            0x00000002 => {
                "The operation adds a private data stream to a file or 
                directory. For example, a virus detector might add checksum information. As the virus
                detector modifies the item, the system generates USN records. This SourceInfo value
                indicates that the modifications did not change the application data in the file."
            }
            0x00000004 => {
                "The operation modified the file to match the
                content of the same file that exists in another member of the replica set for the
                File Replication Service (FRS)."
            }
            _ => {""}
        }
    }
}

pub struct UsnJournalEntry {
    /// Total length of the USN record in bytes.
    pub record_length: u32,
    /// Major version of the USN record format.
    pub major_version: u16,
    /// Minor version of the USN record format.
    pub minor_version: u16,
    /// Unique identifier for updated file in file system. Should be unique to the volume and be
    /// stable until the file is deleted. Set to `std::u64::MAX` if a unique ID could not be
    /// established for the file.
    pub file_reference_number: u64,
    /// Unique identifier for the parent of the USN record file or directory.
    /// See `file_reference_number`.
    pub parent_file_reference_number: u64,
    /// Value uniquely identifying the USN record on its source volume. Must be greater than zero
    /// and must be set to zero if no USN records have been logged for the file or directory
    /// associated with the record.
    pub usn: i64,
    /// System time at which the USN record was created. Source value is a signed 64-bit integer
    /// representing the number of 100-nanosecond intervals since January 1, 1601 UTC.
    pub time_stamp: DateTime<Utc>,
    /// Flags indicating reasons for the changes that have accumulated in this file/directory
    /// since it was opened.
    pub reason: UsnReasonFlags,
    /// Flag indicating additional information about the source of the file/directory change.
    pub source_info: UsnSourceInfoFlags,
    /// Unique security identifier internal to the object store.
    pub security_id: u32,
    /// Attributes associated with the file or directory. Attributes of associated streams are
    /// excluded.
    pub file_attributes: FileAttributeFlags,
    /// Length of the record `file_name` attribute.
    pub file_name_length: u16,
    /// The offset from the beginning of the structure at which the `file_name` attribute begings.
    pub file_name_offset: u16,
    /// Unicode representation of the record's file or directory name.
    pub file_name: String,
}

impl UsnJournalEntry {
    pub fn from_buffer<S: Read>(stream: &mut S) -> crate::err::Result<UsnJournalEntry> {
        let record_length = stream.read_u32::<LittleEndian>()?;
        let major_version = stream.read_u16::<LittleEndian>()?;
        let minor_version = stream.read_u16::<LittleEndian>()?;
        let file_reference_number = stream.read_u64::<LittleEndian>()?;
        let parent_file_reference_number = stream.read_u64::<LittleEndian>()?;
        let usn = stream.read_i64::<LittleEndian>()?;

        let time_stamp = WinTimestamp::from_reader(stream)
            .map_err(Error::failed_to_read_windows_time)?
            .to_datetime();

        let reason = UsnReasonFlags::from_bits_truncate(stream.read_u32::<LittleEndian>()?);
        let source_info =
            UsnSourceInfoFlags::from_bits_truncate(stream.read_u32::<LittleEndian>()?);

        let security_id = stream.read_u32::<LittleEndian>()?;

        let file_attributes =
            FileAttributeFlags::from_bits_truncate(stream.read_u32::<LittleEndian>()?);

        let file_name_length = stream.read_u16::<LittleEndian>()?;
        let file_name_offset = stream.read_u16::<LittleEndian>()?;

        let mut name_buffer = vec![0; file_name_length as usize];
        stream.read_exact(&mut name_buffer)?;

        let file_name = match UTF_16LE.decode(&name_buffer, DecoderTrap::Ignore) {
            Ok(s) => s,
            Err(_e) => return Err(Error::InvalidFilename {}),
        };

        Ok(UsnJournalEntry {
            record_length,
            major_version,
            minor_version,
            file_reference_number,
            parent_file_reference_number,
            usn,
            time_stamp,
            reason,
            source_info,
            security_id,
            file_attributes,
            file_name_length,
            file_name_offset,
            file_name,
        })
    }
}

pub trait ParseUsnJournal {
    fn iter_entries(
        &mut self,
    ) -> Box<dyn Iterator<Item = crate::err::Result<UsnJournalEntry>> + '_>;
}

pub struct UsnJournalParser<T: Read + Seek> {
    data: T,
}

impl<T: Read + Seek> Iterator for UsnJournalParser<T> {
    type Item = crate::err::Result<UsnJournalEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let start_stream_position = match self.data.stream_position() {
            Ok(val) => val,
            Err(e) => return Some(Err(e.into())),
        };

        // read length of the current USN journal entry
        let record_length = match self.data.read_u32::<LittleEndian>() {
            Ok(val) => val,
            // indicates we've reached the end of the stream
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e.into()))
        };

        // seek to beginning of USN journal entry
        match self.data.seek(SeekFrom::Start(start_stream_position)) {
            Ok(_) => {}
            Err(e) => return Some(Err(e.into())),
        };

        // read USN entry into buffer
        let mut entry_buffer = vec![0; record_length as usize];
        match self.data.read_exact(&mut entry_buffer) {
            Ok(_) => {}
            Err(_) => return None
        }

        // parse buffer to USN journal entry
        let mut cursor = Cursor::new(&mut entry_buffer);
        Some(UsnJournalEntry::from_buffer(&mut cursor))
    }
}

impl UsnJournalParser<BufReader<File>> {
    /// Instantiates an instance of the parser from a file path.
    /// Does not mutate the file contents in any way.
    pub fn from_path(filename: impl AsRef<Path>) -> crate::err::Result<Self> {
        let f = filename.as_ref();
        let usn_fh = File::open(f).map_err(|e| Error::failed_to_open_file(f, e))?;
        Ok(Self {
            data: BufReader::with_capacity(4096, usn_fh),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use crate::tests::fixtures::usn_journal_sample;
    use crate::usn_journal::entry::UsnJournalParser;

    const BUFFER: &[u8] = &[
        0x60,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x68,0x91,
        0x3B,0x2A,0x02,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x80,0xBC,0x04,0x00,0x00,0x00,
        0x53,0xC7,0x8B,0x18,0xC5,0xCC,0xCE,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x20,0x20,0x00,0x00,0x20,0x00,0x3C,0x00,0x42,0x00,0x54,0x00,
        0x44,0x00,0x65,0x00,0x76,0x00,0x4D,0x00,0x61,0x00,0x6E,0x00,0x61,0x00,0x67,0x00,
        0x65,0x00,0x72,0x00,0x2E,0x00,0x6C,0x00,0x6F,0x00,0x67,0x00,0x00,0x00,0x00,0x00
    ];

    #[test]
    fn test_record() {
        let mut parser = UsnJournalParser { data: Cursor::new(BUFFER) };
        let record = parser.next().unwrap().unwrap();

        assert_eq!(record.record_length, 96);
        assert_eq!(record.major_version, 2);
        assert_eq!(record.minor_version, 0);
        // assert_eq!(record.file_reference.entry, 115);
        // assert_eq!(record.file_reference.sequence, 37224);
        // assert_eq!(record.parent_reference.entry, 141883);
        // assert_eq!(record.parent_reference.sequence, 7);
        assert_eq!(record.usn, 20342374400);
        assert_eq!(format!("{}", record.time_stamp), "2013-10-19 12:16:53.276040 UTC");
        assert_eq!(record.reason.bits(), 2);
        assert_eq!(record.source_info.bits(), 0);
        assert_eq!(record.security_id, 0);
        assert_eq!(record.file_attributes.bits(), 8224);
        assert_eq!(record.file_name_length, 32);
        assert_eq!(record.file_name_offset, 60);
        assert_eq!(record.file_name, "BTDevManager.log");
    }

    // entrypoint for clion profiler.
    #[test]
    fn test_process_usn_journal() {
        let sample = usn_journal_sample();

        let parser = UsnJournalParser::from_path(sample).unwrap();

        let mut count = 0;
        for record in parser.map(|x| x.unwrap()) {
            assert_eq!(record.record_length, 96);
            assert_eq!(record.major_version, 2);
            assert_eq!(record.minor_version, 0);
            // assert_eq!(record.file_reference.entry, 115);
            // assert_eq!(record.file_reference.sequence, 37224);
            // assert_eq!(record.parent_reference.entry, 141883);
            // assert_eq!(record.parent_reference.sequence, 7);
            assert_eq!(record.usn, 20342374400);
            assert_eq!(format!("{}", record.time_stamp), "2013-10-19 12:16:53.276040 UTC");
            assert_eq!(record.reason.bits(), 2);
            assert_eq!(record.source_info.bits(), 0);
            assert_eq!(record.security_id, 0);
            assert_eq!(record.file_attributes.bits(), 8224);
            assert_eq!(record.file_name_length, 32);
            assert_eq!(record.file_name_offset, 60);
            assert_eq!(record.file_name, "BTDevManager.log");

            count += 1;
        }

        assert!(count > 0)
    }
}
