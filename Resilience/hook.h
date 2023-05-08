#pragma once

#define HOOK_SIZE	12

typedef struct _HOOK {
	VOID	*HookAddress;
	VOID	*OriginalAddress;
	UINT8	Stub[HOOK_SIZE];
	UINT8	ModifiedStub[HOOK_SIZE];
} HOOK, *PHOOK;


VOID
EFIAPI
InitHook(
	IN OUT PHOOK	Hook,
	IN VOID			*AddressToHook,
	IN VOID			*HookAddr
);

VOID
EFIAPI
InstallHook(
	IN PHOOK Hook
);

VOID
EFIAPI
UninstallHook(
	IN PHOOK Hook
);

///////
EFI_STATUS
EFIAPI
CompromiseBootmgfw(
	IN EFI_HANDLE BootmgfwHandle
);

EFI_STATUS
EFIAPI
CompromiseWinload(
	IN VOID* ImageBase,
	IN UINTN ImageSize,
	IN EFI_IMAGE_NT_HEADERS64* NtHeaders64
);
///////
