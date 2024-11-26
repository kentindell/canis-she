# Library for software emulation of SHE HSM.

A software implemention in embedded C for the SHE HSM. Omits the secure boot functionality of SHE. Keys are held in NVRAM via an API, and typically stored in a block of flash memory (a proper HSM stores keys in secure NVRAM).
