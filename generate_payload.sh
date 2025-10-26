#!/bin/bash
# Extract payload bytes from the compiled payload object file

# Compile the payload
nasm -f elf64 sources/payload.s -o objects/payload.o

# Extract the .text section as binary
objcopy -O binary --only-section=.text objects/payload.o objects/payload.bin

# Generate a C header file with the payload
{
    echo "/* Auto-generated payload from payload.s */"
    echo "#ifndef PAYLOAD_DATA_H"
    echo "#define PAYLOAD_DATA_H"
    echo ""
    echo "unsigned char code[] = {"
    
    # Convert binary to hex array
    # Read the file byte by byte and format it
    xxd -i < objects/payload.bin | grep -v '^unsigned\|^};' | sed 's/^  //' | sed '$ s/,$//'
    
    echo "};"
    echo ""
    echo "#endif /* PAYLOAD_DATA_H */"
} > sources/payload_data.h

echo "Generated sources/payload_data.h from sources/payload.s"
