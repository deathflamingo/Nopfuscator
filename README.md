# Nopfuscator

## Overview

This tool allows for disassembling x86/x64 shellcode, inserting NOP-equivalent instructions at regular or variable intervals, and reassembling the modified shellcode. It is useful for obfuscation, but has limitations when dealing with shellcode containing strings or certain structured payloads like Donut and Meterpreter.

## Features

- Disassembles x86 and x64 shellcode with labeled branches.
- Inserts NOP-equivalent instructions at static or variable intervals.
- Supports random NOP-equivalent instructions for better obfuscation.
- Outputs modified shellcode in both disassembled and binary formats.
- Allows architecture selection (x86 or x64).

## Usage

### Command-line Arguments

```
usage: nopfuscator.py -i INPUT [-o OUTPUT] (-sf SF | -vfs VFS -vfe VFE) -a ARCHITECTURE [--random] [--show]
```

|Argument|Description|
|---|---|
|`-i, --input`|Input file containing raw shellcode.|
|`-o, --output`|Output file to save modified shellcode.|
|`-sf`|Static frequency: Insert NOPs every `i` lines.|
|`-vfs`|Variable frequency start interval.|
|`-vfe`|Variable frequency end interval (must be used with `-vfs`).|
|`-a, --architecture`|Architecture (`x86` or `x64`).|
|`--random`|Use random NOP-equivalent instructions.|
|`--show`|Print disassembled output before reassembly.|

### Example Usage

#### Insert NOPs at static intervals

```
python script.py -i shellcode.bin -o obfuscated.bin -sf 5 -a x64 --show
```

#### Insert NOPs at variable intervals with random instructions

```
python script.py -i shellcode.bin -o obfuscated.bin -vfs 3 -vfe 7 -a x86 --random
```

## Limitations

### 🚫 Does Not Work With:

- **Donut shellcode**: Due to its structured format, inserting additional instructions breaks execution.
- **Meterpreter payloads**: Meterpreter's payload validation and encoding methods interfere with the modifications, causing corruption.
- **Shellcode with embedded strings**: The script does not handle modifications correctly when dealing with string-containing shellcode.

### Other Considerations:

- The script does not perform validity checks on the modified shellcode, meaning that obfuscation could break execution in some cases.
- The reassembly process assumes standard x86/x64 assembly syntax; deviations could cause incorrect instruction encoding.

## Dependencies

Ensure you have the required Python libraries installed:

```
pip install capstone keystone-engine
```

## Author

This script was created for research and experimentation in shellcode obfuscation and analysis.
