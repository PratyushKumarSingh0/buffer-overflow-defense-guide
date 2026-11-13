# Buffer Overflow Vulnerability Analysis & Secure Remediation

An educational repository providing in-depth analysis of stack-based buffer overflows (CWE-120), runtime memory layout, modern compiler defenses, and secure coding practices in C.

---

## 📌 Table of Contents
1. [Overview](#overview)
2. [Vulnerability Analysis (CWE-120)](#vulnerability-analysis-cwe-120)
3. [Memory Layout & Stack Mechanics](#memory-layout--stack-mechanics)
4. [Source Code Comparison](#source-code-comparison)
   - [Vulnerable Implementation (`vulnerable.c`)](#vulnerable-implementation-vulnerablec)
   - [Remediated Implementation (`patched.c`)](#remediated-implementation-patchedc)
5. [Modern Platform & Compiler Defenses](#modern-platform--compiler-defenses)
6. [Expected Test Results & Verification](#expected-test-results--verification)
7. [Building and Running](#building-and-running)

---

## 1. Overview

* **Vulnerability Class:** Stack-based Buffer Overflow
* **Common Weakness Enumeration:**
  - [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
  - [CWE-676: Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)
* **Impact:** Process crash (Denial of Service), memory corruption, or unauthorized control-flow alteration.

A stack-based buffer overflow occurs when a program writes data beyond the boundary of a buffer allocated on the call stack. Because stack frames store both local variables and function execution state (such as saved frame pointers and return addresses), unbounded writes risk corrupting execution flow.

---

## 2. Vulnerability Analysis (CWE-120)

In traditional C programming, functions such as `gets()` read characters from standard input until a newline or end-of-file is reached. Crucially, `gets()` does not accept a maximum buffer size parameter:

```c
char buffer[64];
gets(buffer); // UNSAFE: Reads unbounded input into a 64-byte destination
```

If the user supplies input longer than 63 bytes (reserving 1 byte for the null terminator `\0`), the excess data spills into adjacent memory on the stack.

---

## 3. Memory Layout & Stack Mechanics

When a function call occurs on x86/x86_64 architectures, a stack frame is constructed:

```text
High Addresses
+-----------------------------------+
| Caller Function Arguments         |
+-----------------------------------+
| Saved Return Address (EIP / RIP)  | <-- Target return address upon function return
+-----------------------------------+
| Saved Frame Pointer (EBP / RBP)   | <-- Base pointer for previous stack frame
+-----------------------------------+
| Compiler Padding / Stack Canary   | <-- Guard value inserted by -fstack-protector
+-----------------------------------+
| Local Variables: char buffer[64]  | <-- Start of allocated array (writes move upwards)
+-----------------------------------+
Low Addresses
```

### The Progression of an Unbounded Write:
1. **0–63 Bytes:** Stored safely within `buffer`.
2. **64–71 Bytes:** Overwrites compiler alignment padding or the stack canary (if enabled).
3. **72–79 Bytes:** Corrupts the saved frame pointer (`%ebp` / `%rbp`).
4. **80+ Bytes:** Overwrites the saved return address (`%eip` / `%rip`).

When the function completes and executes the `ret` instruction, the CPU pops the value from the return address slot into the instruction pointer. If this address is corrupted, the processor halts execution with a memory fault (`SIGSEGV`).

---

## 4. Source Code Comparison

### Vulnerable Implementation (`src/vulnerable.c`)
Demonstrates the hazard of using unconstrained input functions.

```c
#include <stdio.h>

void vulnerable_function(void) {
    char buffer[64];
    printf("Enter input: ");
    
    // UNSAFE: No boundary checking
    gets(buffer);
    
    printf("Received: %s\n", buffer);
}

int main(void) {
    vulnerable_function();
    return 0;
}
```

### Remediated Implementation (`src/patched.c`)
Enforces bounded input reading using `fgets()`.

```c
#include <stdio.h>

#define BUFFER_SIZE 64

void safe_function(void) {
    char buffer[BUFFER_SIZE];
    printf("Enter input: ");
    
    // SAFE: Reads at most sizeof(buffer) - 1 bytes and guarantees null-termination
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        printf("Received: %s", buffer);
    } else {
        perror("Input error");
    }
}

int main(void) {
    safe_function();
    return 0;
}
```

---

## 5. Modern Platform & Compiler Defenses

Modern operating systems and compilers incorporate multiple defensive layers to prevent or mitigate buffer overflow vulnerabilities:

| Mechanism | Flag / Setting | Description |
| :--- | :--- | :--- |
| **Stack Canaries** | `-fstack-protector-strong` | Places a randomized pseudo-random value before the return address. Upon return, the value is verified. If corrupted, `__stack_chk_fail()` aborts execution immediately. |
| **NX / DEP** | Enabled by default (`-Wl,-z,noexecstack`) | Data Execution Prevention marks the stack page as non-executable (`PAGE_READWRITE`), disallowing code execution from stack buffers. |
| **ASLR** | Enabled at OS level (`-fPIE -pie`) | Address Space Layout Randomization randomizes memory segments (stack, heap, libraries) across executions, making memory layouts non-deterministic. |
| **Fortify Source** | `-D_FORTIFY_SOURCE=2` | Replaces vulnerable string and memory operations with bounds-checked variants where size can be determined at compile/run time. |

---

## 6. Expected Test Results & Verification

| Test Scenario | Input Data | Target: `vulnerable` (with Stack Protector) | Target: `patched` (Remediated) |
| :--- | :--- | :--- | :--- |
| **Test 1: Normal Input** | `Hello, World!` (13 bytes) | **Pass:** Outputs text, returns `0`. | **Pass:** Outputs text, returns `0`. |
| **Test 2: Boundary Input** | 63 `'A'` characters | **Pass:** Fits cleanly in 64-byte buffer. | **Pass:** Fits cleanly in 64-byte buffer. |
| **Test 3: Oversized Input** | 100 `'A'` characters | **Fail / Aborted:** Stack canary corrupted. Program triggers `*** stack smashing detected ***: terminated` with exit code `134` (`SIGABRT`). | **Pass:** `fgets` safely reads 63 bytes, truncates excess, maintains stack integrity, and exits with code `0`. |

---

## 7. Building and Running

### Building with Standard Defenses (Recommended)
```bash
# Build the vulnerable version (with modern compiler warnings and canary)
gcc -Wall -Wextra -fstack-protector-strong -o bin/vulnerable src/vulnerable.c

# Build the secure, remediated version
gcc -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o bin/patched src/patched.c
```

### Running Tests
```bash
# Test secure binary with oversized input (100 characters):
python -c "print('A' * 100)" | ./bin/patched
# Output: Received: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# Exit Code: 0
```
