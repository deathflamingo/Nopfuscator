from capstone import *
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_MODE_32
import random
import argparse

def disassemble_with_labels(code_bytes,arch):
    """
    Disassemble x86 code bytes and add branch labels for jump targets
    
    Args:
        code_bytes: Bytes object containing the machine code
        base_address: Base address for the disassembly (default: 0)
    
    Returns:
        String containing disassembled code with branch labels
    """
    base_address=0
    # Initialize disassembler for x86 32-bit
    if arch=="x64":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch=="x86":
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        print("invalid architecture. Only x86 or x64 supported")
    md.detail = True
    
    branch_targets = set()
    for insn in md.disasm(code_bytes, base_address):
        
        if (insn.group(CS_GRP_JUMP) or 
            insn.group(CS_GRP_CALL) or 
            insn.mnemonic.startswith('loop')):  
            
            
            if len(insn.operands) > 0:
                if insn.operands[0].type == CS_OP_IMM:
                    branch_targets.add(insn.operands[0].imm)
                
                elif insn.mnemonic.startswith('loop'):
                    
                    target = insn.address + insn.size + int(insn.op_str, 16)
                    branch_targets.add(target)
    
    
    branch_labels = {addr: f"branch_{i+1}" for i, addr in enumerate(sorted(branch_targets))}
    
    
    output_lines = []
    
    for insn in md.disasm(code_bytes, base_address):
        
        if insn.address in branch_labels:
            output_lines.append(f"{branch_labels[insn.address]}:")
        
        
        insn_str = f"{insn.mnemonic} {insn.op_str}"
        
        
        if (insn.group(CS_GRP_JUMP) or 
            insn.group(CS_GRP_CALL) or 
            insn.mnemonic.startswith('loop')):
            
            if len(insn.operands) > 0:
                if insn.operands[0].type == CS_OP_IMM:
                    target = insn.operands[0].imm
                    if target in branch_labels:
                        insn_str = f"{insn.mnemonic} {branch_labels[target]}"
                
                elif insn.mnemonic.startswith('loop'):
                    target = insn.address + insn.size + int(insn.op_str, 16)
                    if target in branch_labels:
                        insn_str = f"{insn.mnemonic} {branch_labels[target]}"
        
        output_lines.append(insn_str)
    
    return '\n'.join(output_lines)

def insert_static_frequency(text, interval,rand):
    lines = text.split("\n")
    result = []
    randoms=["mov eax, eax","mov ebx, ebx","mov ecx, ecx","mov edx, edx", "mov esi, esi", "mov edi, edi","xchg eax,eax","xchg ebx,ebx","xchg ecx,ecx","xchg edx,edx","xchg esi,esi","xchg edi,edi", "xchg eax,eax\nxchg eax,eax","xchg eax,ebx\nxchg eax,ebx","xchg eax,ecx\nxchg eax,ecx","xchg eax,edx\nxchg eax,edx","xchg eax,esi\nxchg eax,esi","xchg eax,edi\nxchg eax,edi","xchg ebx,ebx\nxchg ebx,ebx","xchg ebx,ecx\nxchg ebx,ecx","xchg ebx,edx\nxchg ebx,edx","xchg ebx,esi\nxchg ebx,esi","xchg ebx,edi\nxchg ebx,edi","xchg ecx,ecx\nxchg ecx,ecx","xchg ecx,edx\nxchg ecx,edx","xchg ecx,esi\nxchg ecx,esi","xchg ecx,edi\nxchg ecx,edi","xchg edx,edx\nxchg edx,edx","xchg edx,esi\nxchg edx,esi","xchg edx,edi\nxchg edx,edi","xchg esi,esi\nxchg esi,esi","xchg esi,edi\nxchg esi,edi","xchg edi,edi\nxchg edi,edi","lea eax,[eax]","lea ebx,[ebx]","lea ecx,[ecx]","lea edx,[edx]","lea esi,[esi]","lea edi,[edi]"]
    for index, line in enumerate(lines, start=1):
        result.append(line)
        if index % interval == 0:
            if rand:
                result.append(randoms[random.randint(0,len(randoms)-1)])
            else:
                result.append("nop")
    
    return "\n".join(result)

def insert_variable_frequency(lines, min_interval, max_interval,rand):
    """Insert 'insertion here' at random intervals between min and max."""
    result = []
    index = 0
    randoms=["mov eax, eax","mov ebx, ebx","mov ecx, ecx","mov edx, edx", "mov esi, esi", "mov edi, edi","xchg eax,eax","xchg ebx,ebx","xchg ecx,ecx","xchg edx,edx","xchg esi,esi","xchg edi,edi", "xchg eax,eax\nxchg eax,eax","xchg eax,ebx\nxchg eax,ebx","xchg eax,ecx\nxchg eax,ecx","xchg eax,edx\nxchg eax,edx","xchg eax,esi\nxchg eax,esi","xchg eax,edi\nxchg eax,edi","xchg ebx,ebx\nxchg ebx,ebx","xchg ebx,ecx\nxchg ebx,ecx","xchg ebx,edx\nxchg ebx,edx","xchg ebx,esi\nxchg ebx,esi","xchg ebx,edi\nxchg ebx,edi","xchg ecx,ecx\nxchg ecx,ecx","xchg ecx,edx\nxchg ecx,edx","xchg ecx,esi\nxchg ecx,esi","xchg ecx,edi\nxchg ecx,edi","xchg edx,edx\nxchg edx,edx","xchg edx,esi\nxchg edx,esi","xchg edx,edi\nxchg edx,edi","xchg esi,esi\nxchg esi,esi","xchg esi,edi\nxchg esi,edi","xchg edi,edi\nxchg edi,edi","lea eax,[eax]","lea ebx,[ebx]","lea ecx,[ecx]","lea edx,[edx]","lea esi,[esi]","lea edi,[edi]"]

    while index < len(lines):
        result.append(lines[index])
        index += 1
        if index < len(lines):
            next_insert = random.randint(min_interval, max_interval)
            if index + next_insert < len(lines):
                index += next_insert
            else:
                index = len(lines)
            if rand:
                result.append(randoms[random.randint(0,len(randoms)-1)])
            else:
                result.append("nop")
    return result
# Example usage
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Insert 'nops into a shellcode at specified intervals. Does not work with shellcode that contains Strings in it.")
    
    parser.add_argument("-i", "--input", required=True, help="Input file")
    parser.add_argument("-o", "--output", help="Output file")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-sf", type=int, help="Static frequency: Insert every ith line.")
    group.add_argument("-vfs", type=int, help="Variable frequency start interval.")

    parser.add_argument("-vfe", type=int, help="Variable frequency end interval (required with -vfs).")
    parser.add_argument("-a", "--architecture", help="Architecture (x86 or x64).")
    parser.add_argument("--random", action="store_true", help="Use random nop equivalents")
    parser.add_argument("--show", action="store_true", help="Prints Disassembly")
    args = parser.parse_args()

    try:
        with open(args.input, "rb") as f:
            buf = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.input}' not found.")
        exit
    

    result = disassemble_with_labels(buf,args.architecture)

    #print(result)
    if args.sf:
        result = insert_static_frequency(result, args.sf,args.random)
    elif args.vfs is not None and args.vfe is not None:
        result = insert_variable_frequency(result, args.vsf, args.vfe,args.random)
    else:
        parser.error("Both -vfs and -vfe must be specified for variable frequency.")


    if args.architecture=="x64":
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
    elif args.architecture=="x86":
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
    if args.show:
        print(result)
    encoding, count = ks.asm(result)
    
    if args.output:
        with open(args.output, "wb") as f:
            f.write(bytes(encoding))
    else:
        print("Shellcode:", "".join(f"\\x{byte:02x}" for byte in encoding))
