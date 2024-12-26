# DMalloc

## Code:
Available upon request (patrick_li@brown.edu or patrickli2021@gmail.com)

## Introduction and Motivation:
One of the unique challenges systems developers face is the explicit management of computer memory allocation. In other, higher-level programming languages, you work with variables/objects without really worrying about where they are in memory, how much space they are taking up, or when to give their memory back to the operating system.

In systems we take a different perspective: dynamic memory is allocated and deallocated manually by the programmer. This gives the programmer the ability to write faster and more efficient code, or low level programs that might not have super fancy languages or runtime environments to implicitly allocate (embedded systems, etc.). But, like most powerful systems assets, dynamic memory can lead to some complex bugs.

## Overview:
DMalloc is a debugging memory allocator that can track information about dynamic memory allocation, catch common memory programming errors (e.g. freeing the same block twice, trying to allocate too much memory, etc.), detect a write outside a dynamically allocated block (e.g. writing 65 bytes into a 64-byte region of memory), and other general programming errors.

This allocator features the use of various pieces of metadata in order to keep track of the allocated block size. The metadata is stored at the beginning of an allocated block, and `dmalloc` returns a pointer to the "payload" of the block (i.e. to the space after the metadata). The metadata values that were stored include a header flag, the size of the allocated memory/payload, a free flag to mark whether a block has been freed or not, and a footer flag that that marks whether the boundary of a particular block has been written into.

## Key Features:
- **Memory Statistics:** In order to retrieve memory allocation statistics, I incremented both the active and total sizes of the regions allocated as well as the active and total calls within `dmalloc()` and then decreased them respectively in `dfree()`. In order to properly change the active size in `dfree()`, the metadata struct was used as well as pointer arithmetic to obtain the correct size to decrement the active size by.
- **Integer Overflow Protection:** DMalloc is robust against integer overflow attacks. This is implemented by mutiplying the number of members in the prospective allocation by the byte size. If dividing this product by the number of items in teh allocated region does not equal the byte size of each element, then we know that integer overflow occurred.
- **Invalid Free and Double Free Detection:** In order to detect these errors, a header flag was added to the metadata struct. This header flag is set to a secret value and if an invalid free occurs, we know that this header has been changed. In other words, this header flag ensures that the payload pointer is at the beginning of an allocated block. In order to detect double frees, a free flag was incorporated into the metadata that marks whether or not a particular pointer has been freed or not.
- **Boundary Write Error Detection:** A **_boundary error_** is when a program reads or writes memory beyond the actual dimensions of an allocated memory block. For boundary error detection, data with a known secret value is added around the allocated block (i.e. the footer flag) and checked to see if the value is changed or not. If it is changed, then the user must have read or wrote memory beyond the dimensions of the allocated block.
- **Memory Leak Reporting and Advanced Reports and Checking:** A memory leak occurs when code allocates a block of memory, but then forgets to free it. Another issue that is checked for is if a pointer is inside a different allocated block. For these functionalities, I utilized 2 hash maps in C++ that linked together a pointer to all the respective data about that pointer, which was represented as a struct. As each pointer was dynamically allocated, I populated both of these maps and then eventually displayed the results. In order to test whether or not the invalid pointer was allocated within a different block, I looped through each pointer stored in a single map and compared it to the pointer being freed. If the pointer being freed was within the bounds of any pointer in the map being looped over, then this issue was displayed to the terminal.
