#include <Uefi.h>

#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/DevicePathFromText.h>
#include <Protocol/SimpleFileSystem.h>

#include <IndustryStandard/PeImage.h>

#include "globals.h"
#include "utils.h"
#include "nt.h"

#define RECORD_CONTAINS(Address, Type, Field)	((Type *)((UINT8 *)Address - (UINT64)(&((Type *)0)->Field)))

VOID
EFIAPI
MemoryCopy(
	IN VOID		*Dest,
	IN VOID		*Src,
	IN UINTN	C
) {
	for(UINT8 *d = Dest, *s = Src; C--; *d++ = *s++);
}

VOID
EFIAPI
SetGlobalPatchStatus(
	IN EFI_STATUS	Status,
	IN CHAR16		*Message,
	IN VOID			*FuncAddr
) {
	OsGlobalPatch.PatchStatus = Status;
	OsGlobalPatch.Message = Message;
	OsGlobalPatch.ExceptionAddress = FuncAddr;
}

BOOLEAN
EFIAPI
CheckForPattern(
	IN UINT8	*Base,
	IN UINT8	*Pattern,
	IN UINTN	PatternLen
) {
	for(; PatternLen; ++Base, ++Pattern, PatternLen--) {
		if((*Pattern != 0xCC) && (*Base != *Pattern))
			return FALSE;
	}

	return TRUE;
}

VOID *
EFIAPI
ScanForPattern(
	IN UINT8	*Base,
	IN UINTN	Size,
	IN UINT8	*Pattern
) {
	UINTN PatternLen = AsciiStrLen(Pattern);
	Size -= PatternLen;

	for(INT32 i = 0; i <= Size; ++i) {
		VOID *Address = &Base[i];
		
		if(CheckForPattern(Address, Pattern, PatternLen))
			return Address;
	}

	return NULL;
}

EFI_IMAGE_NT_HEADERS64 *
EFIAPI
GetNtHeaders64(
	IN VOID		*ImageBase
) {
	EFI_IMAGE_DOS_HEADER *DosHeader;
	EFI_IMAGE_NT_HEADERS64 *NtHeaders64;

	DosHeader = (EFI_IMAGE_DOS_HEADER *)ImageBase;
	if(DosHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	NtHeaders64 = (EFI_IMAGE_NT_HEADERS64 *)((UINT8 *)ImageBase + DosHeader->e_lfanew);
	if(NtHeaders64->Signature != EFI_IMAGE_NT_SIGNATURE)
		return NULL;

	return NtHeaders64;
}

UINT64 
EFIAPI
GetFunctionByName(
	IN UINT8	*NtBase,
	IN CHAR8	*Name
) {
	if(NtBase == NULL || Name == NULL)
		return 0;

	EFI_IMAGE_NT_HEADERS64 *NtHeaders64 = GetNtHeaders64(NtBase);
	if(NtHeaders64 == NULL)
		return 0;

	UINT32 Export = (NtHeaders64->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if(Export) {
		EFI_IMAGE_EXPORT_DIRECTORY *ExportTable = (EFI_IMAGE_EXPORT_DIRECTORY *)(NtBase + Export);

		UINTN NumOfNames = ExportTable->NumberOfNames;
		UINT32 *Names = (UINT32 *)(NtBase + ExportTable->AddressOfNames);

		for (UINTN i = 0; i < NumOfNames; i++) {
			CHAR8 *Function = (CHAR8 *)(NtBase + Names[i]);
			if(AsciiStrCmp(Name, Function) == 0) {
				UINT32 *AddressOfFunc = (UINT32 *)(NtBase + ExportTable->AddressOfFunctions);
				UINT16 *Ordinal = (UINT16 *)(NtBase + ExportTable->AddressOfNameOrdinals);

				return ((UINT64)NtBase + AddressOfFunc[Ordinal[i]]);
			}
		}
	}

	return 0;
}

UINT64
EFIAPI
GetPESize(
	IN UINT8	*Payload
) {
	EFI_IMAGE_NT_HEADERS64 *NtHeaders64 = GetNtHeaders64(Payload);
	if(NtHeaders64 == NULL)
		return 0;

	return NtHeaders64->OptionalHeader.SizeOfImage;
}

EFI_IMAGE_SECTION_HEADER *
EFIAPI
FindSection(
	IN EFI_IMAGE_NT_HEADERS64	*NtHeaders64,
	IN CHAR8					*SectionName
) {
	EFI_IMAGE_SECTION_HEADER *SectionHeader;

	// Yes
	SectionHeader = (EFI_IMAGE_SECTION_HEADER *)RVA(&NtHeaders64->OptionalHeader, NtHeaders64->FileHeader.SizeOfOptionalHeader);
	if(SectionHeader == NULL)
		return NULL;

	UINT16 SectionCount = NtHeaders64->FileHeader.NumberOfSections;
	for(UINT16 i = 0; i < SectionCount; i++) {
		// Not null terminated
		CHAR8 CurrentSectionName[9];
		MemoryCopy(CurrentSectionName, SectionHeader->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
		CurrentSectionName[9] = '\0';

		if(AsciiStrCmp(SectionName, CurrentSectionName) == 0)
			return SectionHeader;
	
		SectionHeader++;
	}

	return NULL;
}

PKLDR_DATA_TABLE_ENTRY
EFIAPI
FindModule(
	IN LIST_ENTRY	*LoadOrderModule,
	IN CHAR16		*ModuleName
) {
	for(LIST_ENTRY *Current = LoadOrderModule->ForwardLink; Current != LoadOrderModule; Current = Current->ForwardLink) {
		PKLDR_DATA_TABLE_ENTRY Module = RECORD_CONTAINS(Current, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if(Module != NULL) {
			CHAR16 *CurrentModuleName = Module->BaseDllName.Buffer;
			UINTN Length = Module->BaseDllName.Length;

			if(StrnCmp(ModuleName, CurrentModuleName, Length) == 0)
				return Module;
		}
	}

	return NULL;
}

EFI_DEVICE_PATH *
EFIAPI
GetBootmanagerDevicePath(
	IN CHAR16	*Path
) {
	EFI_DEVICE_PATH* DevicePath = NULL;
	UINTN HandlesValue;
	EFI_HANDLE* Handles;
	EFI_STATUS Status;

	Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandlesValue, &Handles);
	if (EFI_ERROR(Status)) {
		Print(L"[!] Cannot locate filesystem handles...\n\r");

		return NULL;
	}

	EFI_FILE_IO_INTERFACE* FileSystem;
	EFI_FILE_HANDLE Volume;
	for (UINTN i = 0; i < HandlesValue; i++) {
		Status = gBS->OpenProtocol(Handles[i], &gEfiSimpleFileSystemProtocolGuid, (VOID**)&FileSystem, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (EFI_ERROR(Status))
			continue;

		Status = FileSystem->OpenVolume(FileSystem, &Volume);
		if (EFI_ERROR(Status)) {
			Print(L"[!] Cannot open volume of filesystem..\n\r");

			return NULL;
		}

		EFI_FILE_HANDLE CurrentFile;
		Status = Volume->Open(Volume, &CurrentFile, Path, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
		if (!EFI_ERROR(Status)) {
			Volume->Close(CurrentFile);

			DevicePath = FileDevicePath(Handles[i], Path);
		}

		gBS->CloseProtocol(Handles[i], &gEfiSimpleFileSystemProtocolGuid, gImageHandle, NULL);
	}

	gBS->FreePool(Handles);

	return DevicePath;
}
