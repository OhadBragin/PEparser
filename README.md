# PEparser

## Building

### Using CMake (Windows, Linux, macOS, CLion)
```bash
cmake -B build
cmake --build build
```

### Direct Compilation

**GCC / Clang (Linux, macOS, MinGW):**
```bash
gcc -O2 PEparser/*.c -o peparser
```

**MSVC (Developer Command Prompt / PowerShell):**
```cmd
cl /O2 PEparser\*.c /Fe:peparser.exe
```

## Running

```bash
# Windows (single-config generators)
build\peparser.exe <binary_file>

# Windows (Visual Studio)
build\Debug\peparser.exe <binary_file>

# Linux / macOS (single-config generators)
./build/peparser <binary_file>

# macOS (Xcode)
./build/Debug/peparser <binary_file>
```
