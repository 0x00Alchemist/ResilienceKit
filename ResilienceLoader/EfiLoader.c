#include <Uefi.h>
#include <Base.h>

#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>

#include <Protocol/SimpleFileSystem.h>

// Some global stuff
EFI_SYSTEM_TABLE		*gST;
EFI_BOOT_SERVICES		*gBS;
EFI_RUNTIME_SERVICES	*gRS;

CHAR8 *gEfiCallerBaseName = "ResilienceLoader";
CONST UINT32 _gUefiDriverRevision = 0;
CONST UINT8  _gDriverUnloadImageCount = 0;

// Useless, but VisualUefi wants them
BOOLEAN mPostEBS = FALSE;
EFI_SYSTEM_TABLE *mDebugST = NULL;


EFI_DEVICE_PATH *
EFIAPI
GetDevicePath(
	IN CHAR16 *Path
) {
	EFI_DEVICE_PATH *DevicePath = NULL;
	UINTN HandlesValue;
	EFI_HANDLE *Handles;
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
	IN EFI_HANDLE		ImageHandle,
	IN EFI_SYSTEM_TABLE *ST
) {
	EFI_STATUS Status = EFI_NOT_FOUND;

	gST = ST;
	gBS = gST->BootServices;
	gRS = gST->RuntimeServices;

	gST->ConOut->ClearScreen(gST->ConOut);
	gST->ConOut->SetAttribute(gST->ConOut, (EFI_YELLOW | EFI_BACKGROUND_BLACK));

	// Reset watchdog timer
	gBS->SetWatchdogTimer(0, 0, 0, NULL);

	Print(L"[+] ResilienceLoader inited at: 0x%llx\n\r");

	CHAR16 *ResiliencePath = L"\\EFI\\Resilience.efi";
	EFI_DEVICE_PATH *ResilienceDevice = GetDevicePath(ResiliencePath);
	if(ResilienceDevice == NULL) {
		Print(L"[!] Cannot find Resilence main binary! Load it manually or change path in ResilienceLoader\\EfiLoader.c\n\r");

		return Status;
	}

	EFI_HANDLE Resilience;
	Status = gBS->LoadImage(TRUE, gImageHandle, ResilienceDevice, NULL, 0, &Resilience);
	if(EFI_ERROR(Status)) {
		Print(L"[!] Cannot load Resilience binary! Status: 0x%llx (%r)\n\r", Status, Status);

		return Status;
	}

	Status = gBS->StartImage(Resilience, NULL, NULL);
	if(EFI_ERROR(Status)) {
		Print(L"[!] Cannot start Resilience binary! Status: 0x%llx (%r)\n\r");

		return Status;
	}
	
	return EFI_SUCCESS;
}