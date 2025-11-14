from keystone import Ks, KS_ARCH_PPC, KS_MODE_PPC64

#######################################################################################
# Register dictionary at start of ACE payload
def ACE_rdict(r3 = 0x81579F34, r12 = 0x803F0F3C, r29 = 0x80A60850):
    rdict = {
        0:  0x00000002,
        1:  0x8040CE00, # stack pointer (DO NOT CHANGE)
        2:  0x803FFD00, # TOC(?) pointer (DO NOT CHANGE)
        3:  r3,         # sScreen = photo3 pixeldata address; island/heap dependent
        4:  0x00000001, 
        5:  0xFFFFFFFF,
        6:  0x000010B8, # check if consistent?
        7:  0x00293D6C, # seems inconsistent, like it can vary by 0x10 or so
        8:  0x00000008,
        9:  0x0011C664, # seems inconsistent
        10: 0x0011C66C, # seems inconsistent
        11: 0x8040CE30,
        12: r12,        # payload start address
        13: 0x803FE0E0, # &sScreen = r13 - 0x6F38 = 0x803F71A8 (DO NOT CHANGE)
        # 14-27: 0x0,   # good registers for 
        28: 0x8003D1DC,
        29: r29,        # PROC_MSG start address; island/heap dependent
        30: 0x804C3B30, # used by safety branch (DO NOT CHANGE)
        31: 0x803E6EA0
        }
    return rdict



#######################################################################################
# Data conversion functions
#######################################################################################
# Convert list of 4 bytes (little endian from Keystone) into a big-endian word
def LE_bytes_to_BE_word(byte_list):
    if len(byte_list) != 4:
        return None
    # Reverse because Keystone outputs LE
    be_bytes = byte_list[::-1]
    return (be_bytes[0] << 24) | (be_bytes[1] << 16) | (be_bytes[2] << 8) | be_bytes[3], be_bytes

# # Convert byte list to binary string (useful for Keystone outputs)
# def bytes_to_bin(byte_list):
#     return " ".join(f"{b:08b}" for b in byte_list)

# # Convert unsigned 32-bit integer to hex string (not sure if used anywhere)
# def get_u32_hex(n):
#     return hex(n & 0xFFFFFFFF).upper().zfill(4)

# Convert integer to binary string with spaces every 'group' bits (default 8)
def format_bin(n, group=8):
    # how many bits are needed to represent n
    bitlen = n.bit_length() or 1
    # round up to nearest multiple of group (default 8)
    width = ((bitlen + group - 1) // group) * group
    # format and split into groups
    b = f"{n:0{width}b}"
    return " ".join(b[i:i+group] for i in range(0, len(b), group))

# Convert hex string to a list of decimal integers (one for each byte); useful for translating controller data -> inputs
def hex_bytes_to_dec(hex_str):
    if hex_str[:2].lower() == '0x':
        hex_str = hex_str[2:]
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

# Split address into base + offset to use for 'lis rA, base' + 'stw rS, offset (rA)'
def split_addr(addr):
    addr = int(addr, 16) if isinstance(addr,str) else addr
    addr_base = addr // 0x10000
    addr_off = addr % 0x10000
    if addr_off >= 0x8000:
        addr_base += 1
        addr_off = 0x10000 - addr_off
    return addr_base, addr_off

#######################################################################################
# Assembly instructions -> hex/binary words
#######################################################################################
# Use Keystone to convert a PowerPC assembly instruction into hex/bin/bytes
def get_ASM_encoding(asm_code, addr=0, ks=None, output_type='hex'):  # addr is the instruction address (for branch offsets)
    if ks is None:
        ks = Ks(KS_ARCH_PPC, KS_MODE_PPC64)
    #print(f'{addr:08X}', asm_code)
    opcode, rest = asm_code.split(' ',1)
    for sym in ['r', '->']:    # keystone doesn't like 'r' in register names or '->' in branch instructions, but I do
        rest = rest.replace(sym, '')
    asm_code = opcode + ' ' + rest

    encoding, count = ks.asm(asm_code, addr=addr, as_bytes=False)
    int_word, BE_bytes = LE_bytes_to_BE_word(encoding)
    hex_word = f'{int_word:08X}'
    match output_type:
        case 'hex':
            return hex_word     # outputs as hex string
        case 'bin':
            return format_bin(int_word)
        case 'bytes':
            return bytes.fromhex(hex_word)


# Get list of (address, value) pairs from file and output the values in desired format
def get_addr_value_pairs_from_file(filename, input_type = 'hex', output_type = 'hex', ks=None):
    addr_value_pairs = []
    with open(filename, 'r') as f:
        #lines = f.readlines()
        for line in f:
            if not line.strip():
                continue
            addr_str, value_str = line.replace(':','').replace('\n','').split(None,1)

            addr, value = addr_value_converter(addr_str, value_str, input_type, output_type, ks=ks)
            addr_value_pairs.append((addr,value))
    return addr_value_pairs


# Convert the value in an (address, value) pair from one data type to another
def addr_value_converter(addr, value, input_type, output_type, ks=None):
    addr = int(addr, 16) if isinstance(addr,str) else addr  # convert addr to an integer if it's still a hex string

    input_type = input_type.lower()
    output_type = output_type.lower()   
    
    if isinstance(value, bytes):
        assert input_type == output_type == 'bytes',                        "Are you really trying to convert FROM bytes to something else?"
        return addr, value
    
    # if isinstance(value, int):
    #     assert (input_type == 'hex') and (output_type in ['hex','bytes']),  "Unpexpected integer"
    #     value = f'{value:08X}'  # convert integer to hex string
    
    if isinstance(value, str):
        if input_type == output_type:
            return addr, value
        
        elif input_type == 'asm':
            v_out = get_ASM_encoding(value, addr=addr, ks=ks, output_type=output_type)
            return (addr, v_out)
        
        elif input_type == 'hex' and output_type == 'bytes':
            return (addr, bytes.fromhex(value))
    
    raise TypeError(f"Unexpected conversion request: value={value}, input_type={input_type}, output_type={output_type}")





#######################################################################################
# PHASE 1 FUNCTIONS
#######################################################################################
'''
During phase 1:
- DME only writes to 0x803F0F3C (pad2 C/LR data)
- All instructions are run several times
- All writes can be done relative to r12=0x803F0F3C
'''

# Get list of PAD2 ASM instructions needed to write hex_to_write at addr_target during phase 1
def phase1_get_instrucs_for_write(addr_target, hex_to_write, r12=0x803F0F3C):
    addr_target = int(addr_target, 16) if isinstance(addr_target,str) else addr_target
    hex_to_write = f'{hex_to_write:08X}' if isinstance(hex_to_write,int) else hex_to_write
    
    # addr_base, addr_off = split_addr(addr_target)
    
    PAD2_instruc_1 = f'lis r14, 0x{hex_to_write[:4]}'
    PAD2_instruc_2 = f'ori r15, r14, 0x{hex_to_write[4:]}'       # use a different register since this will 
    # PAD2_instruc_3 = f'lis r16, 0x{addr_base:04X}'
    # PAD2_instruc_4 = f'stw r15, 0x{addr_off:04X} (r16)'
    # return [PAD2_instruc_1, PAD2_instruc_2, PAD2_instruc_3, PAD2_instruc_4]
    PAD2_instruc_3 = f'stw r15, {addr_target - r12} (r12)'
    return [PAD2_instruc_1, PAD2_instruc_2, PAD2_instruc_3]

    
# Convert a list of (address, instruction) pairs to write during phase 1 into a list of PAD2 instructions (in ASM/hex/bytes) to write with DME
def phase1_get_PAD2_instruction_list(addr_instruc_pairs, r12=0x803F0F3C, ks=None):
    if ks == None:
        ks = Ks(KS_ARCH_PPC, KS_MODE_PPC64)
    PAD2_instruc_list = []
    for (instruc_addr, instruc) in addr_instruc_pairs:
        hex_to_write = get_ASM_encoding(instruc, addr=instruc_addr, ks=ks, output_type='hex')
        #print(f'{instruc_addr:08X}', hex_to_write)
        new_PAD2_instrucs = phase1_get_instrucs_for_write(instruc_addr, hex_to_write, r12=r12)
        PAD2_instruc_list += new_PAD2_instrucs
    # PAD2_hex_list = [get_ASM_encoding(PAD2_instruc, addr=0x803F0F3C, ks=ks, output_type='hex') for PAD2_instruc in PAD2_instruc_list]   # this addr needs to be wherever DME writes in phase 1 (unrelated to whatever r12 is)
    # PAD2_bytes_list = [bytes.fromhex(instruc_hex) for instruc_hex in PAD2_hex_list]
    return PAD2_instruc_list #, PAD2_hex_list, PAD2_bytes_list


# Create phase 1 binary file from list of (address, instruction) pairs
def phase1_create_bin_file(phase1_addr_instruc_pairs, phase1_bytes_file, r12=0x803F0F3C, ks=None):
    PAD2_instruc_list = phase1_get_PAD2_instruction_list(phase1_addr_instruc_pairs, r12=r12, ks=ks)
    with open(phase1_bytes_file,'wb') as f:
        for PAD2_instruc in PAD2_instruc_list:
            PAD2_instruc_bytes = get_ASM_encoding(PAD2_instruc, addr=0x803F0F3C, ks=ks, output_type='bytes')
            f.write(PAD2_instruc_bytes)


#######################################################################################
# PHASE 2 FUNCTIONS
#######################################################################################

# Get list of pad 1-4 ASM instructions needed to write hex_to_write at addr_target during phase 2
def phase2_get_instrucs_for_write(addr_target, hex_to_write):
    addr_target = int(addr_target, 16) if isinstance(addr_target,str) else addr_target
    hex_to_write = f'{hex_to_write:08X}' if isinstance(hex_to_write,int) else hex_to_write
    
    size = len(hex_to_write) // 2
    if size == 4 and (addr_target % 4 == 0):
        PAD_instruc_1 = f'lis r14, 0x{hex_to_write[:4]}'
        PAD_instruc_2 = f'ori r14, r14, 0x{hex_to_write[4:]}'       # can use same register in phase 2
        store = 'stw'
    elif size <= 2:
        PAD_instruc_1 = f'nop'  # inefficient, but it'll be a headache if we don't always do 4-instruction batches
        
        val = int(hex_to_write,16)
        if val >= 0x8000:
            val -= 0x10000  # keystone needs SIMM signs to be explicit
        PAD_instruc_2 = f'li r14, {val}'
        
        if size == 2 and (addr_target % 2 == 0):
            store = 'sth'
        elif size == 1:
            store = 'stb'
    else:
        raise ValueError(f"Bad alignment or hex size -- {addr_target:08X}: {hex_to_write}")
    
    addr_base, addr_off = split_addr(addr_target)
    #print(addr_base, addr_off)

    PAD_instruc_3 = f'lis r15, 0x{addr_base:04X}'
    PAD_instruc_4 = f'{store} r14, 0x{addr_off:04X} (r15)'
    
    return [PAD_instruc_1, PAD_instruc_2, PAD_instruc_3, PAD_instruc_4]


# Convert a list of (address, hex) pairs to write during phase 2 into a list of PAD instructions (in ASM/hex/bytes) to write with DME
def phase2_get_PAD_instruction_list(addr_hex_pairs):
    PAD2_instruc_list = []
    for (addr, hex_to_write) in addr_hex_pairs:
        #print(f'{instruc_addr:08X}', hex_to_write)
        new_PAD2_instrucs = phase2_get_instrucs_for_write(addr, hex_to_write)
        PAD2_instruc_list += new_PAD2_instrucs
    return PAD2_instruc_list


# Create phase 2 binary file from list of (address, hex_to_write) pairs
def phase2_create_bin_file(phase2_addr_hex_pairs, phase2_bin_file, ks = None):
    PAD_instruc_list = phase2_get_PAD_instruction_list(phase2_addr_hex_pairs)
    #print(PAD_instruc_list)
    with open(phase2_bin_file,'wb') as f:
        for PAD_instruc in PAD_instruc_list:
            #print(PAD_instruc)
            PAD_instruc_bytes = get_ASM_encoding(PAD_instruc, addr=0, ks=ks, output_type='bytes')   # will need to edit addr if we do any non brl/bctrl branches during phase 2
            f.write(PAD_instruc_bytes)



#######################################################################################
# Old way I used to create bytes files
#######################################################################################
# # Get bytes list from a file of hex words
# def hexfile2bytes(hexfile):
#     instructions = []
#     with open(hexfile) as f:
#         for line in f:
#             hex_word = line.split('#', 1)[0].strip()    # remove comments & whitespace
#             if hex_word:
#                 #print(hex_word)
#                 instruction = bytes.fromhex(hex_word)
#                 instructions.append(instruction)
#     return instructions

# def create_bytes_file(bytes_list, bytes_filename):
#     with open(bytes_filename, 'wb') as f:
#         for word_bytes in bytes_list:
#             f.write(word_bytes)

#######################################################################################
# Old ASM -> hex/bin functions
#######################################################################################
# # Return hex for "source: b -> target" instructions (should be redundant with Keystone asm)
# def branch_hex(target, source=0x803F0F44):
#     target = int(target, 16) if isinstance(target,str) else target
#     source = int(source, 16) if isinstance(source,str) else source
#     off = target - source
#     if off < 0:
#         off += 0x04000000
#     out = 0x48000000 + off
#     return f'{out:08X}'

# # Same but return binary string
# def branch_bin(target, source):
#     hex_str = branch_hex(target, source)
#     return format_bin(int(hex_str, 16))


# # Return hex for lwz instruction (should be redundant with Keystone asm)
# def lwz_hex(D, A=12, offset=0x8):
#     opcode_bin = '100000' # lwz opcode in binary
#     D_bin = bin(D)[2:].zfill(5)
#     A_bin = bin(A)[2:].zfill(5)
#     if offset < 0:
#         offset += 0x10000
#     offset_bin = bin(offset)[2:].zfill(16)
#     instruction_bin = opcode_bin + D_bin + A_bin + offset_bin
#     instruction_hex = hex(int(instruction_bin, 2)).upper().zfill(8)
#     return instruction_hex


