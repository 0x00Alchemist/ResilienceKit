#include <Uefi.h>

typedef struct _OS_GLOBAL_PATCH {
	EFI_STATUS	PatchStatus;
	CHAR16		*Message;
	VOID		*ExceptionAddress;
} OS_GLOBAL_PATCH, *POS_GLOBAL_PATCH;

OS_GLOBAL_PATCH OsGlobalPatch;

EFI_SYSTEM_TABLE		*gST;
EFI_BOOT_SERVICES		*gBS;
EFI_RUNTIME_SERVICES	*gRS;

