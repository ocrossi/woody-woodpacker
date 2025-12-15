# Woody Woodpacker Test Framework

A Python-based test framework for testing the `woody_woodpacker` executable with various edge cases to ensure the program handles error conditions gracefully without crashing.

## Requirements

- Python 3.6+
- `woody_woodpacker` executable (build with `make`)

## Running Tests

1. First, build the woody_woodpacker executable:
   ```bash
   make
   ```

2. Run the test framework:
   ```bash
   cd tests
   python3 test_woody.py
   ```

   Or with a custom path to woody_woodpacker:
   ```bash
   python3 test_woody.py --woody-path /path/to/woody_woodpacker
   ```

## Test Categories

The test framework covers the following edge cases:

### Argument Handling
- No arguments provided
- Too many arguments provided
- Empty string argument

### File Access Errors
- Non-existent file
- Directory as input
- Permission denied (no read access)
- Broken symlink
- Symlink to valid file

### Invalid File Content
- Empty file
- Plain text file
- Random binary data
- Very small file (1 byte)
- File with special characters in filename

### ELF Format Validation
- Partial ELF magic number
- 32-bit ELF file (only 64-bit supported)
- Big-endian ELF file
- Invalid ELF type (relocatable instead of executable)
- Truncated ELF header
- Corrupted program headers offset
- Wrong ELF version
- Zero-filled ELF after magic
- Invalid ELF header size field

### Missing Sections/Segments
- Missing PT_NOTE section (required for code injection)
- Missing .text section (required for encryption)

### Valid Input Testing
- Standard 64-bit executable
- PIE (Position Independent Executable)

## Exit Codes

- **0**: All tests passed
- **1**: One or more tests failed

## Test Output

The test framework provides colored output:
- ✓ (green): Test passed
- ✗ (red): Test failed  
- ○ (yellow): Test skipped

## Adding New Tests

To add a new test case:

1. Create a new method in the `WoodyTester` class with the `test_` prefix:
   ```python
   def test_my_new_test(self):
       """Test: Description of what this test does."""
       # Create test file or setup
       filepath = self.create_temp_file("test_file", b'content')
       
       # Run woody_woodpacker
       ret, stdout, stderr = self.run_woody([filepath])
       
       # Assert expected behavior
       if ret != 0:  # or other condition
           self.add_result(
               "test_my_new_test",
               TestResult.PASSED,
               f"Description of success",
               ret, stdout, stderr
           )
       else:
           self.add_result(
               "test_my_new_test",
               TestResult.FAILED,
               f"Description of failure",
               ret, stdout, stderr
           )
   ```

2. Add the test method to the `run_all_tests()` method's `test_methods` list.

## Helper Methods

- `create_temp_file(filename, content)`: Create a temporary file with binary content
- `create_minimal_elf64(filename, ...)`: Create a minimal valid ELF64 file for testing
- `run_woody(args, timeout=10)`: Execute woody_woodpacker with given arguments
