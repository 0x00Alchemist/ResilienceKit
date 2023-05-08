# Resilience
Another UEFI bootkit that drops payload in RT phase of OS.

## Usage
1. Move your payload to the file Payload.h
2. Create a bootable flash drive with <b>\EFI\Boot</b> structure. In the <b>Boot</b> folder you should put <b>ResilienceLoader</b>, renamed <b>bootx64.efi</b>. In the folder <b>EFI</b> must be the bootkit itself (not the bootloader). If needed, the path to the bootkit can be changed in ResilienceLoader.
3. Reboot with bootable flash drive

## Compilation
The project uses the EDK2 library to compile the bootkit and the bootloader. Depending on your framework to work with UEFI applications, you will need EDK2 anyway. This project uses VisualUEFI as its framework.

## Test
Should work mostly on Windows 10 (21H2, 22H2).