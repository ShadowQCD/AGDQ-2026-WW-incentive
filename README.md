## Summary
This repo is designed for testing controller-based ACE payloads in the NTSC-U version of _The Legend of Zelda: The Wind Waker_ (GZLE01) on a Dolphin emulator, in preparation for EJ125's Wind Waker incentive at AGDQ 2026.

The idea is to simulate whatever method will be used to inject the payload on console, which we're currently thinking will be a USB Gecko transferring bytes from a binary file to controller data at a rate of ~1 kHz.

## Contents
`main.ipynb` is a Jupyter notebook that uses the python package `dolphin-memory-engine` (DME) to hook to a Dolphin instance and repeatedly write bytes to controller 1-4 data to simulate rapid TAS inputs, which can be used to write custom ASM payloads.

The full process is broken down into several phases:
| Phase    | Description |
|----------|-------------|
| 0        | Set up pads 2-4 before the run, then triggers ACE as usual to initiate a holding loop with pads 2-4. |
| 0.5      | Execute `main.ipynb` (run all), which contains the remaining phases: |
| 1        | Use DME writes to pad 2 from `phase1.bin` to set up input detection & cache management for phase 2. |
| 1.5      | Perform a DME write to pads 3–4 for the first time to transition into phase 2. |
| 2 (main) | Perform as many DME writes to pads 1–4 as needed to create the showcase payload (`phase2.bin`). |
| 3        | Use DME writes to do any necessary cleanup, then finish with `b -> 0x80215664` to resume gameplay. |

`phase1_addr_instruc_pairs.txt` and `phase2_addr_hex_pairs.txt` are used to generate the binary files `phase1.bin` and `phase2.bin`, whose bytes are directly written to controller data with DME.

### NOTE: To experiment with different payloads, edit `phase2_addr_hex_pairs.txt`

`helper_funcs.py` contains several functions that can do useful things like:
* Convert an ASM instruction string into its hex/binary/bytes encoding.
* Read a list of desired (address, ASM_instruction) or (address, hex) pairs from a file and output a list of ASM instructions that will perform the desired writes to those addresses.
* Convert a list of ASM instructions into a binary file for phase 1/2 whose bytes can be directly written to controller data with DME to execute the phase.

Running `python interactive_ASM_encoder.py` from a terminal will initiate a command line interface that's handy for quickly converting an ASM instruction into its hex and binary encodings; type `help` while it's running for more information.

ASM encoding is done through the python package `keystone-engine`.
It doesn't have an option for the specific Gekko architecture that the GameCube uses, but its `KS_MODE_PPC64` seems basically identical as far as I can tell (other than endianness I haven't noticed any discrepancies).

## Installation
#### 1. Clone the repo to your local machine
```
git clone https://github.com/ShadowQCD/AGDQ26-WW-incentive.git
cd <repo>
```
#### 2. Install required packages (`dolphin-memory-engine` and `keystone-engine`)
```
pip install -r requirements.txt
```