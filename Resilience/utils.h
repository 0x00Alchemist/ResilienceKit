#include <Uefi.h>

#include <IndustryStandard/PeImage.h>

#include "nt.h"

#define Sleep(N)						(gBS->Stall(N * 1000000))
#define RVA(Address, Offset)			((UINTN)Address + Offset)
#define CALC_ADDRESS(Address, Offset)	((VOID *)((UINT8 *)Address + *(INT32 *)((UINT8 *)Address + Offset) + Offset + sizeof(INT32)))
		

VOID
EFIAPI
MemoryCopy(
	IN VOID		*Dest,
	IN VOID		*Src,
	IN UINTN	C
);

VOID
EFIAPI
memset(
	IN VOID		*Dest,
	IN UINTN	Value,
	IN UINTN	C
);

VOID
EFIAPI
SetGlobalPatchStatus(
	IN EFI_STATUS	Status,
	IN CHAR16		*Message,
	IN VOID			*FuncAddr
);

VOID *
EFIAPI
ScanForPattern(
	IN UINT8	*Base,
	IN UINTN	Size,
	IN UINT8	*Pattern
);

EFI_IMAGE_NT_HEADERS64 *
EFIAPI
GetNtHeaders64(
	IN VOID		*ImageBase
);

UINT64
EFIAPI
GetFunctionByName(
	IN UINT8	*NtBase,
	IN CHAR8	*Name
);

UINT64
EFIAPI
GetPESize(
	IN UINT8	*Payload
);

EFI_IMAGE_SECTION_HEADER *
EFIAPI
FindSection(
	IN EFI_IMAGE_NT_HEADERS64	*NtHeaders64,
	IN CHAR8					*SectionName
);

PKLDR_DATA_TABLE_ENTRY
EFIAPI
FindModule(
	IN LIST_ENTRY	*LoadOrderModule,
	IN CHAR16		*ModuleName
);

EFI_DEVICE_PATH *
EFIAPI
GetBootmanagerDevicePath(
	IN CHAR16	*Path
);
