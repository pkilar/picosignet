/* RP2040 flash/RAM layout for usbhsm.
 *
 * The last six 4 KiB sectors of the 2 MiB flash are carved out of the FLASH
 * region so firmware code/rodata can never grow into the persistent HSM state.
 * The linker errors if the binary exceeds the firmware region — a hard ceiling
 * that protects the config/key/counter sectors. See docs/FLASH_LAYOUT.md.
 *
 *   offset      size    purpose
 *   0x000000    256 B   BOOT2 (second-stage bootloader)
 *   0x000100    ~2 MiB  FLASH  firmware code + rodata (XIP)   [ends at 0x1FA000]
 *   0x1FA000    4 KiB   CONFIG_A      ]
 *   0x1FB000    4 KiB   CONFIG_B      ]
 *   0x1FC000    4 KiB   KEY_A         ]  reserved for hsm-core storage,
 *   0x1FD000    4 KiB   KEY_B         ]  NOT part of the FLASH region
 *   0x1FE000    4 KiB   PIN_COUNTER   ]
 *   0x1FF000    4 KiB   RESERVED      ]
 */
MEMORY {
    BOOT2 : ORIGIN = 0x10000000, LENGTH = 0x100
    /* Firmware region: 0x10000100 .. 0x101FA000 (just under 2 MiB, less boot2). */
    FLASH : ORIGIN = 0x10000100, LENGTH = 0x1FA000 - 0x100
    RAM   : ORIGIN = 0x20000000, LENGTH = 264K
}

SECTIONS {
    /* Second-stage bootloader (provided by embassy-rp) sits at the very start
     * of flash. */
    .boot2 ORIGIN(BOOT2) :
    {
        KEEP(*(.boot2));
    } > BOOT2
} INSERT BEFORE .text;
