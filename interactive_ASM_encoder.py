from keystone import Ks, KS_ARCH_PPC, KS_MODE_PPC64
from helper_funcs import get_ASM_encoding, format_bin

# Execute in a terminal with 'python YOUR/PATH/TO/interactive_ASM_encoder.py'
def main():
    print("PowerPC Assembly → Hex / Binary (type 'help' for instructions and 'quit' to exit)")
    ks = Ks(KS_ARCH_PPC, KS_MODE_PPC64)

    while True:
        try:
            asm_code = input(">>> ").strip()
            if asm_code.lower() in ("quit", "exit"):
                break
            if asm_code.lower() == 'help':
                print("Type a PowerPC ASM instruction (e.g. lis r3, 0x80AB) to see its hex and binary encodings.")
                print("If you want to specify the instruction address, type it before the instruction (e.g. 0x80000000: b -> 0x8000ABCD).")
                print("The encoding uses Keystone's PPC64 architecture, which may not be completely identical to the specific Gekko architecture that GameCube uses, so some discrepancies may be possible (although I haven't noticed any so far)")
                continue
            if not asm_code:
                continue
            
            
            addr = 0
            if asm_code[0] in '08':
                addr, asm_code = asm_code.replace(':','').split(' ',1)
                addr = int(addr, 16)

            hex_word = get_ASM_encoding(asm_code, addr=addr, ks=ks, output_type='hex')
            # encoding, count = ks.asm(asm_code, addr=addr, as_bytes=False)
            # int_word, BE_bytes = LE_bytes_to_BE_word(encoding)
            # hex_word = f'{int_word:08X}'
            bin_str = format_bin(int(hex_word,16))

            print(f'Hex: {hex_word}')
            print(f'Bin: {bin_str}\n')
            
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    main()