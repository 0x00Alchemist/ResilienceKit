#include <Uefi.h>

#include "utils.h"
#include "hook.h"


VOID
EFIAPI
InitHook(
	IN OUT PHOOK	Hook,
	IN VOID			*AddressToHook,
	IN VOID			*HookAddr
) {
	// Hook template
	UINT8 HookTemplate[] = {
		0x48, 0xB8,											// mov rax, ->
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// <addr>
		0x50,											    // push rax
		0xC3												// ret
	};

	Hook->OriginalAddress = AddressToHook;
	Hook->HookAddress = HookAddr;

	// Copy hook template
	MemoryCopy(HookTemplate + 2, &HookAddr, sizeof(HookAddr));

	// Save original stub
	MemoryCopy(Hook->Stub, AddressToHook, HOOK_SIZE);

	// Save modified stub
	MemoryCopy(Hook->ModifiedStub, HookTemplate, HOOK_SIZE);
}

VOID
EFIAPI
InstallHook(
	IN PHOOK	Hook
) {
	MemoryCopy(Hook->OriginalAddress, Hook->ModifiedStub, HOOK_SIZE);
}

VOID
EFIAPI
UninstallHook(
	IN PHOOK	Hook
) {
	MemoryCopy(Hook->OriginalAddress, Hook->Stub, HOOK_SIZE);
}