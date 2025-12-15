#!/usr/bin/env python3
"""
Test framework for woody_woodpacker.

This test framework verifies that the woody_woodpacker executable handles
various edge cases correctly without crashing.
"""

import argparse
import os
import random
import sys
import subprocess
import tempfile
import struct
import shutil
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Tuple


# ELF Header Size Constants
EXPECTED_ELF64_EHSIZE = 64  # Expected ELF64 header size
INVALID_ELF_EHSIZE = 0x10   # Invalid header size for testing

# String table offset constants
SHSTRTAB_TEXT_NAME_OFFSET = 1    # Offset of ".text\0" in shstrtab
SHSTRTAB_SHSTRTAB_NAME_OFFSET = 7  # Offset of ".shstrtab\0" in shstrtab


class TestResult(Enum):
    """Enumeration of test results."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class TestCase:
    """Data class representing a test case result."""
    name: str
    result: TestResult
    message: str
    return_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None


class WoodyTester:
    """Test framework for woody_woodpacker."""
    
    def __init__(self, woody_path: str = None):
        """Initialize the tester with the path to woody_woodpacker."""
        if woody_path is None:
            # Default to looking for woody_woodpacker in parent directory
            script_dir = Path(__file__).parent
            woody_path = script_dir.parent / "woody_woodpacker"
        
        self.woody_path = Path(woody_path).resolve()
        self.test_results: List[TestCase] = []
        self.temp_dir = None
        
        # Test files directory
        self.test_files_dir = Path(__file__).parent
    
    def setup(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp(prefix="woody_test_")
        # Make sure woody_woodpacker exists
        if not self.woody_path.exists():
            raise FileNotFoundError(f"woody_woodpacker not found at {self.woody_path}")
    
    def teardown(self):
        """Clean up test environment."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def run_woody(self, args: List[str], timeout: int = 10) -> Tuple[int, str, str]:
        """Run woody_woodpacker with given arguments.
        
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        cmd = [str(self.woody_path)] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.temp_dir
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "TIMEOUT"
        except Exception as e:
            return -1, "", str(e)
    
    def add_result(self, name: str, result: TestResult, message: str,
                   return_code: Optional[int] = None,
                   stdout: Optional[str] = None,
                   stderr: Optional[str] = None):
        """Add a test result."""
        self.test_results.append(TestCase(
            name=name,
            result=result,
            message=message,
            return_code=return_code,
            stdout=stdout,
            stderr=stderr
        ))
    
    def create_temp_file(self, filename: str, content: bytes) -> str:
        """Create a temporary file with given content."""
        filepath = os.path.join(self.temp_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(content)
        return filepath
    
    def create_minimal_elf64(self, filename: str, 
                             executable_type: int = 2,  # ET_EXEC
                             include_pt_note: bool = True,
                             include_text_section: bool = True) -> str:
        """Create a minimal valid ELF64 file."""
        # ELF Header constants
        EI_MAG = b'\x7fELF'
        EI_CLASS = b'\x02'  # 64-bit
        EI_DATA = b'\x01'  # Little endian
        EI_VERSION = b'\x01'
        EI_OSABI = b'\x00'
        EI_PADDING = b'\x00' * 8
        
        e_type = struct.pack('<H', executable_type)  # ET_EXEC=2 or ET_DYN=3
        e_machine = struct.pack('<H', 0x3E)  # x86-64
        e_version = struct.pack('<I', 1)
        e_entry = struct.pack('<Q', 0x401000)  # Entry point
        
        # Calculate offsets
        ehdr_size = 64
        phdr_size = 56
        shdr_size = 64
        
        num_phdrs = 2 if include_pt_note else 1  # PT_LOAD + optional PT_NOTE
        num_shdrs = 3 if include_text_section else 1  # NULL + .text + .shstrtab
        
        phdr_offset = ehdr_size
        shdr_offset = phdr_offset + (num_phdrs * phdr_size)
        
        # Section string table content
        shstrtab = b'\x00.text\x00.shstrtab\x00'
        shstrtab_offset = shdr_offset + (num_shdrs * shdr_size)
        
        # Code section
        text_offset = shstrtab_offset + len(shstrtab)
        text_content = b'\xc3' * 16  # ret instruction padding
        
        e_phoff = struct.pack('<Q', phdr_offset)
        e_shoff = struct.pack('<Q', shdr_offset)
        e_flags = struct.pack('<I', 0)
        e_ehsize = struct.pack('<H', ehdr_size)
        e_phentsize = struct.pack('<H', phdr_size)
        e_phnum = struct.pack('<H', num_phdrs)
        e_shentsize = struct.pack('<H', shdr_size)
        e_shnum = struct.pack('<H', num_shdrs)
        e_shstrndx = struct.pack('<H', num_shdrs - 1)  # Last section is .shstrtab
        
        # Build ELF header
        elf_header = (EI_MAG + EI_CLASS + EI_DATA + EI_VERSION + EI_OSABI +
                      EI_PADDING + e_type + e_machine + e_version + e_entry +
                      e_phoff + e_shoff + e_flags + e_ehsize + e_phentsize +
                      e_phnum + e_shentsize + e_shnum + e_shstrndx)
        
        # Build program headers
        # PT_LOAD header
        pt_load = struct.pack('<IIQQQQQQ',
            1,  # p_type = PT_LOAD
            5,  # p_flags = PF_R | PF_X
            text_offset,  # p_offset
            0x401000,  # p_vaddr
            0x401000,  # p_paddr
            len(text_content),  # p_filesz
            len(text_content),  # p_memsz
            0x1000  # p_align
        )
        
        program_headers = pt_load
        
        # PT_NOTE header
        if include_pt_note:
            pt_note = struct.pack('<IIQQQQQQ',
                4,  # p_type = PT_NOTE
                4,  # p_flags = PF_R
                0,  # p_offset
                0,  # p_vaddr
                0,  # p_paddr
                0,  # p_filesz
                0,  # p_memsz
                4  # p_align
            )
            program_headers += pt_note
        
        # Build section headers
        # NULL section header
        null_shdr = struct.pack('<IIQQQQIIQQ',
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        )
        
        section_headers = null_shdr
        
        if include_text_section:
            # .text section header
            text_shdr = struct.pack('<IIQQQQIIQQ',
                1,  # sh_name (offset in shstrtab)
                1,  # sh_type = SHT_PROGBITS
                6,  # sh_flags = SHF_ALLOC | SHF_EXECINSTR
                0x401000,  # sh_addr
                text_offset,  # sh_offset
                len(text_content),  # sh_size
                0,  # sh_link
                0,  # sh_info
                16,  # sh_addralign
                0   # sh_entsize
            )
            section_headers += text_shdr
        
        # .shstrtab section header
        shstrtab_name_offset = SHSTRTAB_SHSTRTAB_NAME_OFFSET if include_text_section else SHSTRTAB_TEXT_NAME_OFFSET
        shstrtab_shdr = struct.pack('<IIQQQQIIQQ',
            shstrtab_name_offset,  # sh_name
            3,  # sh_type = SHT_STRTAB
            0,  # sh_flags
            0,  # sh_addr
            shstrtab_offset,  # sh_offset
            len(shstrtab),  # sh_size
            0,  # sh_link
            0,  # sh_info
            1,  # sh_addralign
            0   # sh_entsize
        )
        section_headers += shstrtab_shdr
        
        # Assemble the ELF file
        elf_content = elf_header + program_headers + section_headers + shstrtab + text_content
        
        return self.create_temp_file(filename, elf_content)
    
    # ========== Test Methods ==========
    
    def test_no_arguments(self):
        """Test: Running woody without arguments."""
        ret, stdout, stderr = self.run_woody([])
        
        # Should exit with error (non-zero) but not crash
        if ret != 0:
            self.add_result(
                "test_no_arguments",
                TestResult.PASSED,
                f"Correctly rejected no arguments (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_no_arguments",
                TestResult.FAILED,
                f"Should have rejected no arguments but exited with code 0",
                ret, stdout, stderr
            )
    
    def test_too_many_arguments(self):
        """Test: Running woody with too many arguments."""
        ret, stdout, stderr = self.run_woody(["arg1", "arg2", "arg3"])
        
        if ret != 0:
            self.add_result(
                "test_too_many_arguments",
                TestResult.PASSED,
                f"Correctly rejected too many arguments (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_too_many_arguments",
                TestResult.FAILED,
                f"Should have rejected too many arguments",
                ret, stdout, stderr
            )
    
    def test_nonexistent_file(self):
        """Test: Running woody with a non-existent file."""
        ret, stdout, stderr = self.run_woody(["/nonexistent/file/path"])
        
        if ret != 0:
            self.add_result(
                "test_nonexistent_file",
                TestResult.PASSED,
                f"Correctly handled non-existent file (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_nonexistent_file",
                TestResult.FAILED,
                f"Should have failed for non-existent file",
                ret, stdout, stderr
            )
    
    def test_empty_file(self):
        """Test: Running woody with an empty file."""
        filepath = self.create_temp_file("empty_file", b'')
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_empty_file",
                TestResult.PASSED,
                f"Correctly handled empty file (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_empty_file",
                TestResult.FAILED,
                f"Should have failed for empty file",
                ret, stdout, stderr
            )
    
    def test_text_file(self):
        """Test: Running woody with a plain text file."""
        content = b"This is just a plain text file, not an ELF binary.\n"
        filepath = self.create_temp_file("text_file.txt", content)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_text_file",
                TestResult.PASSED,
                f"Correctly rejected text file (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_text_file",
                TestResult.FAILED,
                f"Should have rejected text file",
                ret, stdout, stderr
            )
    
    def test_partial_elf_magic(self):
        """Test: File with partial ELF magic number."""
        # Only first 2 bytes of magic
        content = b'\x7fE'
        filepath = self.create_temp_file("partial_magic", content)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_partial_elf_magic",
                TestResult.PASSED,
                f"Correctly handled partial ELF magic (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_partial_elf_magic",
                TestResult.FAILED,
                f"Should have failed for partial ELF magic",
                ret, stdout, stderr
            )
    
    def test_elf32_file(self):
        """Test: Running woody with a 32-bit ELF file."""
        # Create a minimal 32-bit ELF header
        elf32_header = (
            b'\x7fELF' +  # Magic
            b'\x01' +     # 32-bit
            b'\x01' +     # Little endian
            b'\x01' +     # ELF version
            b'\x00' * 9 +  # Padding
            b'\x02\x00' +  # ET_EXEC
            b'\x03\x00' +  # i386
            b'\x01\x00\x00\x00' +  # Version
            b'\x00\x00\x00\x00' +  # Entry point
            b'\x34\x00\x00\x00' +  # Program header offset
            b'\x00\x00\x00\x00' +  # Section header offset
            b'\x00\x00\x00\x00' +  # Flags
            b'\x34\x00' +  # ELF header size
            b'\x20\x00' +  # Program header entry size
            b'\x00\x00' +  # Program header count
            b'\x28\x00' +  # Section header entry size
            b'\x00\x00' +  # Section header count
            b'\x00\x00'  # Section name string table index
        )
        filepath = self.create_temp_file("elf32_file", elf32_header)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_elf32_file",
                TestResult.PASSED,
                f"Correctly rejected 32-bit ELF (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_elf32_file",
                TestResult.FAILED,
                f"Should have rejected 32-bit ELF",
                ret, stdout, stderr
            )
    
    def test_big_endian_elf(self):
        """Test: Running woody with a big-endian ELF file."""
        # Create ELF header with big endian flag
        elf_be_header = (
            b'\x7fELF' +  # Magic
            b'\x02' +     # 64-bit
            b'\x02' +     # Big endian
            b'\x01' +     # ELF version
            b'\x00' * 9 +  # Padding
            b'\x00\x02' +  # ET_EXEC (big endian)
            b'\x00\x3e' +  # x86-64 (big endian)
            b'\x00\x00\x00\x01'  # Version (big endian)
        )
        # Pad to make it look like a header
        elf_be_header += b'\x00' * (64 - len(elf_be_header))
        filepath = self.create_temp_file("big_endian_elf", elf_be_header)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_big_endian_elf",
                TestResult.PASSED,
                f"Correctly rejected big-endian ELF (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_big_endian_elf",
                TestResult.FAILED,
                f"Should have rejected big-endian ELF",
                ret, stdout, stderr
            )
    
    def test_invalid_elf_type(self):
        """Test: ELF file with invalid type (not executable)."""
        # Create ELF header for a relocatable file (ET_REL = 1)
        elf_header = (
            b'\x7fELF' +  # Magic
            b'\x02' +     # 64-bit
            b'\x01' +     # Little endian
            b'\x01' +     # ELF version
            b'\x00' * 9 +  # Padding
            b'\x01\x00' +  # ET_REL (relocatable, not executable)
            b'\x3e\x00' +  # x86-64
            b'\x01\x00\x00\x00' +  # Version
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # Entry point
            b'\x40\x00\x00\x00\x00\x00\x00\x00' +  # Program header offset
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # Section header offset
            b'\x00\x00\x00\x00' +  # Flags
            b'\x40\x00' +  # ELF header size
            b'\x38\x00' +  # Program header entry size
            b'\x00\x00' +  # Program header count
            b'\x40\x00' +  # Section header entry size
            b'\x00\x00' +  # Section header count
            b'\x00\x00'  # Section name string table index
        )
        filepath = self.create_temp_file("relocatable_elf", elf_header)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_invalid_elf_type",
                TestResult.PASSED,
                f"Correctly rejected relocatable ELF (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_invalid_elf_type",
                TestResult.FAILED,
                f"Should have rejected relocatable ELF",
                ret, stdout, stderr
            )
    
    def test_truncated_elf_header(self):
        """Test: Truncated ELF header."""
        # Valid magic but truncated header
        content = b'\x7fELF\x02\x01\x01' + b'\x00' * 20  # Less than full header
        filepath = self.create_temp_file("truncated_header", content)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_truncated_elf_header",
                TestResult.PASSED,
                f"Correctly handled truncated ELF header (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_truncated_elf_header",
                TestResult.FAILED,
                f"Should have failed for truncated ELF header",
                ret, stdout, stderr
            )
    
    def test_corrupted_program_headers(self):
        """Test: ELF with corrupted program headers offset."""
        # Create ELF header pointing to invalid program header location
        elf_header = (
            b'\x7fELF' +  # Magic
            b'\x02' +     # 64-bit
            b'\x01' +     # Little endian
            b'\x01' +     # ELF version
            b'\x00' * 9 +  # Padding
            b'\x02\x00' +  # ET_EXEC
            b'\x3e\x00' +  # x86-64
            b'\x01\x00\x00\x00' +  # Version
            b'\x00\x10\x40\x00\x00\x00\x00\x00' +  # Entry point
            b'\xff\xff\xff\x00\x00\x00\x00\x00' +  # Program header offset (invalid, too large)
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # Section header offset
            b'\x00\x00\x00\x00' +  # Flags
            b'\x40\x00' +  # ELF header size
            b'\x38\x00' +  # Program header entry size
            b'\x01\x00' +  # Program header count
            b'\x40\x00' +  # Section header entry size
            b'\x00\x00' +  # Section header count
            b'\x00\x00'  # Section name string table index
        )
        filepath = self.create_temp_file("corrupted_phdr", elf_header)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_corrupted_program_headers",
                TestResult.PASSED,
                f"Correctly handled corrupted program headers (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_corrupted_program_headers",
                TestResult.FAILED,
                f"Should have failed for corrupted program headers",
                ret, stdout, stderr
            )
    
    def test_no_pt_note_section(self):
        """Test: Valid ELF without PT_NOTE section."""
        filepath = self.create_minimal_elf64("no_pt_note", include_pt_note=False)
        ret, stdout, stderr = self.run_woody([filepath])
        
        # woody_woodpacker requires PT_NOTE to inject code
        if ret != 0:
            self.add_result(
                "test_no_pt_note_section",
                TestResult.PASSED,
                f"Correctly handled missing PT_NOTE (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_no_pt_note_section",
                TestResult.FAILED,
                f"Should have handled missing PT_NOTE section",
                ret, stdout, stderr
            )
    
    def test_no_text_section(self):
        """Test: ELF without .text section."""
        filepath = self.create_minimal_elf64("no_text", include_text_section=False)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_no_text_section",
                TestResult.PASSED,
                f"Correctly handled missing .text section (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_no_text_section",
                TestResult.FAILED,
                f"Should have failed for missing .text section",
                ret, stdout, stderr
            )
    
    def test_directory_as_input(self):
        """Test: Running woody with a directory as input."""
        ret, stdout, stderr = self.run_woody([self.temp_dir])
        
        if ret != 0:
            self.add_result(
                "test_directory_as_input",
                TestResult.PASSED,
                f"Correctly rejected directory as input (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_directory_as_input",
                TestResult.FAILED,
                f"Should have rejected directory as input",
                ret, stdout, stderr
            )
    
    def test_permission_denied(self):
        """Test: Running woody with a file without read permission."""
        filepath = self.create_temp_file("no_read_perm", b'test content')
        os.chmod(filepath, 0o000)
        
        ret, stdout, stderr = self.run_woody([filepath])
        
        # Restore permissions for cleanup
        os.chmod(filepath, 0o644)
        
        if ret != 0:
            self.add_result(
                "test_permission_denied",
                TestResult.PASSED,
                f"Correctly handled permission denied (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_permission_denied",
                TestResult.FAILED,
                f"Should have failed for permission denied",
                ret, stdout, stderr
            )
    
    def test_random_binary_data(self):
        """Test: Running woody with random binary data."""
        random_data = bytes([random.randint(0, 255) for _ in range(1000)])
        filepath = self.create_temp_file("random_data", random_data)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_random_binary_data",
                TestResult.PASSED,
                f"Correctly handled random binary data (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_random_binary_data",
                TestResult.FAILED,
                f"Should have rejected random binary data",
                ret, stdout, stderr
            )
    
    def test_very_small_file(self):
        """Test: Running woody with a very small file (1 byte)."""
        filepath = self.create_temp_file("one_byte", b'\x00')
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_very_small_file",
                TestResult.PASSED,
                f"Correctly handled very small file (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_very_small_file",
                TestResult.FAILED,
                f"Should have rejected very small file",
                ret, stdout, stderr
            )
    
    def test_special_characters_in_filename(self):
        """Test: Running woody with special characters in filename."""
        filepath = self.create_temp_file("file with spaces.txt", b'test')
        ret, stdout, stderr = self.run_woody([filepath])
        
        # Should fail gracefully (not an ELF)
        if ret != 0:
            self.add_result(
                "test_special_characters_in_filename",
                TestResult.PASSED,
                f"Correctly handled special filename (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_special_characters_in_filename",
                TestResult.FAILED,
                f"Should have handled special filename gracefully",
                ret, stdout, stderr
            )
    
    def test_symlink_to_valid_file(self):
        """Test: Running woody with a symlink to a valid ELF."""
        test_hello = self.test_files_dir / "test_hello"
        if test_hello.exists():
            link_path = os.path.join(self.temp_dir, "link_to_hello")
            os.symlink(str(test_hello), link_path)
            ret, stdout, stderr = self.run_woody([link_path])
            
            if ret == 0:
                # Check if woody output file was created
                woody_output = os.path.join(self.temp_dir, "woody")
                if os.path.exists(woody_output):
                    self.add_result(
                        "test_symlink_to_valid_file",
                        TestResult.PASSED,
                        f"Successfully processed symlink to valid ELF",
                        ret, stdout, stderr
                    )
                else:
                    self.add_result(
                        "test_symlink_to_valid_file",
                        TestResult.FAILED,
                        f"No output file created",
                        ret, stdout, stderr
                    )
            else:
                self.add_result(
                    "test_symlink_to_valid_file",
                    TestResult.FAILED,
                    f"Failed to process symlink (exit code: {ret})",
                    ret, stdout, stderr
                )
        else:
            self.add_result(
                "test_symlink_to_valid_file",
                TestResult.SKIPPED,
                "test_hello not available"
            )
    
    def test_symlink_to_nonexistent(self):
        """Test: Running woody with a broken symlink."""
        link_path = os.path.join(self.temp_dir, "broken_link")
        os.symlink("/nonexistent/target", link_path)
        ret, stdout, stderr = self.run_woody([link_path])
        
        if ret != 0:
            self.add_result(
                "test_symlink_to_nonexistent",
                TestResult.PASSED,
                f"Correctly handled broken symlink (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_symlink_to_nonexistent",
                TestResult.FAILED,
                f"Should have failed for broken symlink",
                ret, stdout, stderr
            )
    
    def test_valid_executable(self):
        """Test: Running woody with a valid test executable."""
        test_hello = self.test_files_dir / "test_hello"
        if test_hello.exists():
            # Copy test_hello to temp dir for testing
            test_copy = os.path.join(self.temp_dir, "test_hello")
            shutil.copy(str(test_hello), test_copy)
            
            ret, stdout, stderr = self.run_woody([test_copy])
            
            if ret == 0:
                woody_output = os.path.join(self.temp_dir, "woody")
                if os.path.exists(woody_output):
                    # Try running the output
                    try:
                        result = subprocess.run(
                            [woody_output],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if "WOODY" in result.stdout:
                            self.add_result(
                                "test_valid_executable",
                                TestResult.PASSED,
                                f"Successfully infected executable, WOODY message displayed",
                                ret, stdout, stderr
                            )
                        else:
                            self.add_result(
                                "test_valid_executable",
                                TestResult.PASSED,
                                f"Successfully created woody output file",
                                ret, stdout, stderr
                            )
                    except Exception as e:
                        self.add_result(
                            "test_valid_executable",
                            TestResult.PASSED,
                            f"Output file created (execution test: {e})",
                            ret, stdout, stderr
                        )
                else:
                    self.add_result(
                        "test_valid_executable",
                        TestResult.FAILED,
                        f"No output file created",
                        ret, stdout, stderr
                    )
            else:
                self.add_result(
                    "test_valid_executable",
                    TestResult.FAILED,
                    f"Failed to process valid executable (exit code: {ret})",
                    ret, stdout, stderr
                )
        else:
            self.add_result(
                "test_valid_executable",
                TestResult.SKIPPED,
                "test_hello not available"
            )
    
    def test_pie_executable(self):
        """Test: Running woody with a PIE executable."""
        test_pie = self.test_files_dir / "test_hello_pie"
        if test_pie.exists():
            test_copy = os.path.join(self.temp_dir, "test_hello_pie")
            shutil.copy(str(test_pie), test_copy)
            
            ret, stdout, stderr = self.run_woody([test_copy])
            
            if ret == 0:
                woody_output = os.path.join(self.temp_dir, "woody")
                if os.path.exists(woody_output):
                    self.add_result(
                        "test_pie_executable",
                        TestResult.PASSED,
                        f"Successfully processed PIE executable",
                        ret, stdout, stderr
                    )
                else:
                    self.add_result(
                        "test_pie_executable",
                        TestResult.FAILED,
                        f"No output file created for PIE",
                        ret, stdout, stderr
                    )
            else:
                self.add_result(
                    "test_pie_executable",
                    TestResult.FAILED,
                    f"Failed to process PIE executable (exit code: {ret})",
                    ret, stdout, stderr
                )
        else:
            self.add_result(
                "test_pie_executable",
                TestResult.SKIPPED,
                "test_hello_pie not available"
            )
    
    def test_elf_wrong_version(self):
        """Test: ELF with wrong version field."""
        elf_header = (
            b'\x7fELF' +  # Magic
            b'\x02' +     # 64-bit
            b'\x01' +     # Little endian
            b'\x00' +     # Invalid version (should be 1)
            b'\x00' * 9 +  # Padding
            b'\x02\x00' +  # ET_EXEC
            b'\x3e\x00' +  # x86-64
            b'\x00\x00\x00\x00'  # Invalid version
        )
        elf_header += b'\x00' * (64 - len(elf_header))
        filepath = self.create_temp_file("wrong_version", elf_header)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_elf_wrong_version",
                TestResult.PASSED,
                f"Correctly rejected wrong ELF version (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_elf_wrong_version",
                TestResult.FAILED,
                f"Should have rejected wrong ELF version",
                ret, stdout, stderr
            )
    
    def test_zero_filled_elf_size(self):
        """Test: ELF file with all zeros after magic."""
        content = b'\x7fELF' + b'\x00' * 100
        filepath = self.create_temp_file("zero_filled", content)
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_zero_filled_elf_size",
                TestResult.PASSED,
                f"Correctly handled zero-filled ELF (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_zero_filled_elf_size",
                TestResult.FAILED,
                f"Should have failed for zero-filled ELF",
                ret, stdout, stderr
            )
    
    def test_elf_invalid_ehsize(self):
        """Test: ELF with invalid header size field."""
        elf_header = bytearray(
            b'\x7fELF' +  # Magic
            b'\x02' +     # 64-bit
            b'\x01' +     # Little endian
            b'\x01' +     # Version
            b'\x00' * 9 +  # Padding
            b'\x02\x00' +  # ET_EXEC
            b'\x3e\x00' +  # x86-64
            b'\x01\x00\x00\x00' +  # Version
            b'\x00' * 24  # Entry, phoff, shoff, flags
        )
        elf_header += struct.pack('<H', INVALID_ELF_EHSIZE)  # Wrong ehsize (should be 64)
        elf_header += b'\x00' * (EXPECTED_ELF64_EHSIZE - len(elf_header))
        filepath = self.create_temp_file("invalid_ehsize", bytes(elf_header))
        ret, stdout, stderr = self.run_woody([filepath])
        
        if ret != 0:
            self.add_result(
                "test_elf_invalid_ehsize",
                TestResult.PASSED,
                f"Correctly rejected invalid ELF header size (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_elf_invalid_ehsize",
                TestResult.FAILED,
                f"Should have rejected invalid ELF header size",
                ret, stdout, stderr
            )
    
    def test_empty_string_argument(self):
        """Test: Running woody with an empty string argument."""
        ret, stdout, stderr = self.run_woody([""])
        
        if ret != 0:
            self.add_result(
                "test_empty_string_argument",
                TestResult.PASSED,
                f"Correctly handled empty string argument (exit code: {ret})",
                ret, stdout, stderr
            )
        else:
            self.add_result(
                "test_empty_string_argument",
                TestResult.FAILED,
                f"Should have handled empty string argument",
                ret, stdout, stderr
            )
    
    def run_all_tests(self):
        """Run all test cases."""
        self.setup()
        
        test_methods = [
            self.test_no_arguments,
            self.test_too_many_arguments,
            self.test_nonexistent_file,
            self.test_empty_file,
            self.test_text_file,
            self.test_partial_elf_magic,
            self.test_elf32_file,
            self.test_big_endian_elf,
            self.test_invalid_elf_type,
            self.test_truncated_elf_header,
            self.test_corrupted_program_headers,
            self.test_no_pt_note_section,
            self.test_no_text_section,
            self.test_directory_as_input,
            self.test_permission_denied,
            self.test_random_binary_data,
            self.test_very_small_file,
            self.test_special_characters_in_filename,
            self.test_symlink_to_valid_file,
            self.test_symlink_to_nonexistent,
            self.test_valid_executable,
            self.test_pie_executable,
            self.test_elf_wrong_version,
            self.test_zero_filled_elf_size,
            self.test_elf_invalid_ehsize,
            self.test_empty_string_argument,
        ]
        
        for test in test_methods:
            try:
                test()
            except Exception as e:
                self.add_result(
                    test.__name__,
                    TestResult.FAILED,
                    f"Exception during test: {str(e)}"
                )
        
        self.teardown()
    
    def print_results(self):
        """Print test results summary."""
        print("\n" + "=" * 70)
        print("WOODY WOODPACKER TEST RESULTS")
        print("=" * 70 + "\n")
        
        passed = sum(1 for t in self.test_results if t.result == TestResult.PASSED)
        failed = sum(1 for t in self.test_results if t.result == TestResult.FAILED)
        skipped = sum(1 for t in self.test_results if t.result == TestResult.SKIPPED)
        
        for test in self.test_results:
            status_icon = {
                TestResult.PASSED: "✓",
                TestResult.FAILED: "✗",
                TestResult.SKIPPED: "○"
            }[test.result]
            
            color = {
                TestResult.PASSED: "\033[92m",  # Green
                TestResult.FAILED: "\033[91m",  # Red
                TestResult.SKIPPED: "\033[93m"  # Yellow
            }[test.result]
            
            reset = "\033[0m"
            
            print(f"{color}{status_icon} {test.name}{reset}")
            print(f"   {test.message}")
            if test.result == TestResult.FAILED and test.stderr:
                print(f"   stderr: {test.stderr[:100]}...")
            print()
        
        print("-" * 70)
        print(f"Total: {len(self.test_results)} tests")
        print(f"  \033[92mPassed:  {passed}\033[0m")
        print(f"  \033[91mFailed:  {failed}\033[0m")
        print(f"  \033[93mSkipped: {skipped}\033[0m")
        print("-" * 70)
        
        return failed == 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Test framework for woody_woodpacker")
    parser.add_argument(
        "--woody-path",
        help="Path to woody_woodpacker executable",
        default=None
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    try:
        tester = WoodyTester(woody_path=args.woody_path)
        tester.run_all_tests()
        success = tester.print_results()
        sys.exit(0 if success else 1)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please build woody_woodpacker first with 'make'")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
