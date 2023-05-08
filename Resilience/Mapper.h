#pragma once

EFI_STATUS
EFIAPI
MpMapPayload(
	IN UINT8	*NtBase,	// For restoring IAT
	IN UINT8	*PayloadBase,
	IN UINT8	*Buffer,
	OUT VOID	**EntryPoint
);