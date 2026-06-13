/* RP2350 flash/RAM layout for PicoSignet (Waveshare RP2350-One, 4 MiB QSPI flash).
 *
 * The last six 4 KiB sectors of the 4 MiB flash are carved out of the FLASH
 * region so firmware code/rodata can never grow into the persistent HSM state.
 * The linker errors if the binary exceeds the firmware region — a hard ceiling
 * that protects the config/key/counter sectors. See docs/FLASH_LAYOUT.md.
 *
 *   offset      size     purpose
 *   0x000000    ~4 MiB   FLASH  firmware code + rodata (XIP)  [ends at 0x3FA000]
 *   0x3FA000    4 KiB    CONFIG_A      ]
 *   0x3FB000    4 KiB    CONFIG_B      ]
 *   0x3FC000    4 KiB    KEY_A         ]  reserved for hsm-core storage,
 *   0x3FD000    4 KiB    KEY_B         ]  NOT part of the FLASH region
 *   0x3FE000    4 KiB    PIN_COUNTER   ]
 *   0x3FF000    4 KiB    RESERVED      ]
 *
 * No BOOT2: the RP2350 bootrom boots directly from an IMAGE_DEF block
 * (.start_block below) embedded in the first 4 KiB of the image.
 */
MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 0x3FA000
    RAM   : ORIGIN = 0x20000000, LENGTH = 512K
}

SECTIONS {
    /* RP2350 boot ROM info: the IMAGE_DEF block (embassy_rp::block::ImageDef in
     * main.rs) must sit right after the vector table so the bootrom and
     * picotool find it within the first 4 KiB of flash. */
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH
} INSERT AFTER .vector_table;

/* Move .text to start after the boot info. */
_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    /* Picotool 'Binary Info' entries (present only if emitted; harmless if empty). */
    .bi_entries : ALIGN(4)
    {
        __bi_entries_start = .;
        KEEP(*(.bi_entries));
        . = ALIGN(4);
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

SECTIONS {
    /* Boot ROM extra info: terminates the block loop started by .start_block. */
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
    } > FLASH
} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);
