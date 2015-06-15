#ifndef ZW_OPENFILE_H
# define ZW_OPENFILE_H

NTSTATUS NTAPI NewNtOpenFile(
    PHANDLE				phFile,
    ACCESS_MASK			DesiredAccess,
    POBJECT_ATTRIBUTES	ObjectAttributes,
    PIO_STATUS_BLOCK	IoStatusBlock,
    ULONG				ShareAccess,
    ULONG				OpenOptions);

#endif