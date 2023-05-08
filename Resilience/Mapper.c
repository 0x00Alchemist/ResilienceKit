#include <Uefi.h>
#include <Library/UefiLib.h>

#include "Payload.h"
#include "globals.h"
#include "utils.h"
#include "nt.h"


EFI_STATUS
EFIAPI
MpMapPayload(
	IN UINT8	*NtBase,	// For restoring IAT
	IN UINT8	*PayloadBase,
	IN UINT8	*Buffer,
	OUT VOID	**EntryPoint
) {
	// Get payload headers
	EFI_IMAGE_NT_HEADERS64 *NtHeaders64 = GetNtHeaders64(PayloadBase);
	if(NtHeaders64 == NULL)
		return EFI_NOT_FOUND;

	MemoryCopy(Buffer, PayloadBase, NtHeaders64->OptionalHeader.SizeOfHeaders);

	// Map sections
	EFI_IMAGE_SECTION_HEADER *Sections = (EFI_IMAGE_SECTION_HEADER *)((UINT64)&NtHeaders64->OptionalHeader + NtHeaders64->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < NtHeaders64->FileHeader.NumberOfSections; i++)
		MemoryCopy(Buffer + Sections[i].VirtualAddress, PayloadBase + Sections[i].PointerToRawData, Sections[i].SizeOfRawData);

	EFI_IMAGE_BASE_RELOCATION *Relocations = (EFI_IMAGE_BASE_RELOCATION *)(Buffer + NtHeaders64->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	INT32 ImageDelta = (INT32)((UINT64)NtHeaders64->OptionalHeader.ImageBase - (UINT64)Buffer);

	// Resolve current relocations
	while(Relocations->VirtualAddress) {
		if(Relocations->SizeOfBlock >= sizeof(EFI_IMAGE_BASE_RELOCATION)) {
			UINT8 *RelocsBase = (Buffer + Relocations->VirtualAddress);
			UINT16 *RelocsData = (UINT16 *)(Relocations + 1);
			UINT32 RelocsCount = ((Relocations->SizeOfBlock - sizeof(EFI_IMAGE_BASE_RELOCATION)) / sizeof(UINT16));

			for(INTN i = 0; i < RelocsCount; i++) {
				UINT16 Data = *RelocsData;
				UINT16 Type = Data >> 12;
				UINT16 Offset = Data & 0xFFF;

				switch(Type) {
					case EFI_IMAGE_REL_BASED_ABSOLUTE:
					case EFI_IMAGE_REL_BASED_HIGHADJ:
					break;
					case EFI_IMAGE_REL_BASED_DIR64:
						*(INT64 *)(RelocsBase + Offset) += ImageDelta;
					break;
					case EFI_IMAGE_REL_BASED_HIGH:
						*(INT16 *)(RelocsBase + Offset) += ((ImageDelta >> 16) & 0xFFFF);
					break;
					case EFI_IMAGE_REL_BASED_LOW:
						*(INT16 *)(RelocsBase + Offset) += ImageDelta & 0xFFFF;
					break;
					case EFI_IMAGE_REL_BASED_HIGHLOW:
						*(UINT32 *)(RelocsBase + Offset) += ImageDelta;
					break;
					default:
						return EFI_UNSUPPORTED;
				}
			}
		}

		Relocations = (EFI_IMAGE_BASE_RELOCATION *)((UINT64)Relocations + Relocations->SizeOfBlock);
	}

	// Some of the structure definitions from EDK2 do not have the necessary fields, 
	// so we use structures directly from Windows
	IMAGE_IMPORT_DESCRIPTOR *Imports = (IMAGE_IMPORT_DESCRIPTOR *)(Buffer + NtHeaders64->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Resolve current imports
	for(IMAGE_IMPORT_DESCRIPTOR *ControlDescriptor = Imports; ControlDescriptor->Characteristics; ControlDescriptor++) {
		IMAGE_THUNK_DATA *Original = (IMAGE_THUNK_DATA *)(Buffer + ControlDescriptor->OriginalFirstThunk);
		IMAGE_THUNK_DATA *First = (IMAGE_THUNK_DATA *)(Buffer + ControlDescriptor->FirstThunk);

		while(Original->u1.AddressOfData) {
			IMAGE_IMPORT_BY_NAME *iName = (IMAGE_IMPORT_BY_NAME *)(Buffer + Original->u1.AddressOfData);
			CHAR8 *Name = iName->Name;

			UINT64 FunctionAddress = GetFunctionByName(NtBase, Name);

			if(!FunctionAddress) 
				return EFI_NOT_FOUND;

			First->u1.Function = FunctionAddress;

			Original++;
			First++;
		}
	}

	*EntryPoint = (Buffer + NtHeaders64->OptionalHeader.AddressOfEntryPoint);

	return EFI_SUCCESS;
}
