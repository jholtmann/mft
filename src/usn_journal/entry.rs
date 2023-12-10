use crate::attribute::FileAttributeFlags;
use bitflags::bitflags;
use chrono::{DateTime, Utc};

bitflags! {
    /// Flag sources:
    /// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d2a2b53e-bf78-4ef3-90c7-21b918fab304>
    ///
    pub struct UsnReasonFlag: u32 {
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

impl UsnReasonFlag {
    pub fn get_meaning(&self) -> &str {
        match self {
            &UsnReasonFlag::USN_REASON_BASIC_INFO_CHANGE => {
                "A user has either changed one or more files or directory attributes 
                (such as read-only, hidden, archive, or sparse) or one or more time stamps."
            }
            &UsnReasonFlag::USN_REASON_CLOSE => "The file or directory is closed.",
            &UsnReasonFlag::USN_REASON_COMPRESSION_CHANGE => {
                "The compression state of the file or directory is changed from (or to) compressed."
            }
            &UsnReasonFlag::USN_REASON_DATA_EXTEND => {
                "The file or directory is extended (added to)."
            }
            &UsnReasonFlag::USN_REASON_DATA_OVERWRITE => {
                "The data in the file or directory is overwritten."
            }
            &UsnReasonFlag::USN_REASON_DATA_TRUNCATION => "The file or directory is truncated.",
            &UsnReasonFlag::USN_REASON_EA_CHANGE => {
                "The user made a change to the extended 
                attributes of a file or directory. These NTFS file system attributes are not
                accessible to nonnative applications. This USN reason does not appear under normal
                system usage but can appear if an application or utility bypasses the Win32 API and
                uses the native API to create or modify extended attributes of a file or directory."
            }
            &UsnReasonFlag::USN_REASON_ENCRYPTION_CHANGE => {
                "The file or directory is encrypted or decrypted."
            }
            &UsnReasonFlag::USN_REASON_FILE_CREATE => {
                "The file or directory is created for the first time."
            }
            &UsnReasonFlag::USN_REASON_FILE_DELETE => "The file or directory is deleted.",
            &UsnReasonFlag::USN_REASON_HARD_LINK_CHANGE => {
                "A hard link is added to (or removed from) the file or directory."
            }
            &UsnReasonFlag::USN_REASON_INDEXABLE_CHANGE => {
                "A user changes the FILE_ATTRIBUTE_NOT_CONTEXT_INDEXED attribute. That is, the
                user changes the file or directory from one in which content can be indexed to
                one in which content cannot be indexed, or vice versa."
            }
            &UsnReasonFlag::USN_REASON_NAMED_DATA_EXTEND => {
                "The one (or more) named data stream for a file is extended (added to)."
            }
            &UsnReasonFlag::USN_REASON_NAMED_DATA_OVERWRITE => {
                "The data in one (or more) named data stream for a file is overwritten."
            }
            &UsnReasonFlag::USN_REASON_NAMED_DATA_TRUNCATION => {
                "One (or more) named data stream for a file is truncated."
            }
            &UsnReasonFlag::USN_REASON_OBJECT_ID_CHANGE => {
                "The object identifier of a file or directory is changed."
            }
            &UsnReasonFlag::USN_REASON_RENAME_NEW_NAME => {
                "A file or directory is renamed, and the file name in the USN_RECORD structure
                is the new name."
            }
            &UsnReasonFlag::USN_REASON_RENAME_OLD_NAME => {
                "The file or directory is renamed, and the file name in the USN_RECORD structure
                is the previous name."
            }
            &UsnReasonFlag::USN_REASON_REPARSE_POINT_CHANGE => {
                "The reparse point that is contained in a file or directory is changed, or a
                reparse point is added to (or deleted from) a file or directory."
            }
            &UsnReasonFlag::USN_REASON_SECURITY_CHANGE => {
                "A change is made in the access rights to a file or directory."
            }
            &UsnReasonFlag::USN_REASON_STREAM_CHANGE => {
                "A named stream is added to (or removed from) a file, or a named stream is renamed."
            }
            &UsnReasonFlag::USN_REASON_INTEGRITY_CHANGE => {
                "A change is made in the integrity status of a file or directory."
            }
        }
    }
}

bitflags! {
    /// Flag sources:
    /// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d2a2b53e-bf78-4ef3-90c7-21b918fab304>
    ///
    pub struct UsnSourceInfoFlag: u32 {
        const USN_SOURCE_DATA_MANAGEMENT            = 0x00000001;
        const USN_SOURCE_AUXILIARY_DATA             = 0x00000002;
        const USN_SOURCE_REPLICATION_MANAGEMENT     = 0x00000004;
    }
}

impl UsnSourceInfoFlag {
    pub fn get_meaning(&self) -> &str {
        match self {
            &UsnSourceInfoFlag::USN_SOURCE_DATA_MANAGEMENT => {
                "The operation provides information about a change to 
                the file or directory that was made by the operating system. For example, a change
                journal record with this SourceInfo value is generated when the Remote Storage
                system moves data from external to local storage. This SourceInfo value indicates
                that the modifications did not change the application data in the file."
            }
            &UsnSourceInfoFlag::USN_SOURCE_AUXILIARY_DATA => {
                "The operation adds a private data stream to a file or 
                directory. For example, a virus detector might add checksum information. As the virus
                detector modifies the item, the system generates USN records. This SourceInfo value
                indicates that the modifications did not change the application data in the file."
            }
            &UsnSourceInfoFlag::USN_SOURCE_REPLICATION_MANAGEMENT => {
                "The operation modified the file to match the
                content of the same file that exists in another member of the replica set for the
                File Replication Service (FRS)."
            }
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
    pub reason: UsnReasonFlag,
    /// Flag indicating additional information about the source of the file/directory change.
    pub source_info: UsnSourceInfoFlag,
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
