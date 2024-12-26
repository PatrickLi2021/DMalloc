Project 2: DMalloc
===================

<!-- TODO: Fill this out. -->

## Design Overview:
For DMalloc, I filled in the implementations of the following functions: `dmalloc()` and `dfree()` (which were the main functions) as well as `get_statistics()`, `dcalloc()`, and `print_leak_report()`.

In order to fill out `get_statistics()` method, I incremented both the active and total sizes as well as the active and total calls within `dmalloc()` and decreased them respectively in `dfree()`. In order to properly change the active size in `dfree()`, I created a metadata struct within dmalloc.hh that initially stored the size as one of its fields. Using pointer arithmetic, I was able to extract this value in `dfree()` and obtain the correct size to decrement the active size by.

For the next part of the project, I implemented integer overflow protection in `dcalloc()` by first multiplying the number of members in the prospective allocation by the byte size. If dividing this product by the number of items in the allocated does not equal the byte size of each element, then we know that integer overflow occurred.

In order to detect invalid and double frees, I first add a header flag to my metadata struct that I created earlier for the statistics. I set this header flag to a particular/secret value and if an invalid free occurrs, I know that this header flag has been changed. In other words, this header flag ensures that the payload pointer is at the beginning of an allocated block. In order to detect double frees, I also include a free flag in my metadata struct that marks whether or not a particular pointer has been freed or not.

For boundary error detection, I added data with a known secret value around the allocated block (i.e. the footer flag) and made sure that this value wasn't changed. If it was, then I know that the user must have read or wrote memory beyond the dimensions of the allocated block.

Lastly, for the leak reporting and advanced reports, I utilized two hash maps in C++ that linked together a pointer to all the respective data about that pointer, which I represented as a struct. As each pointer was `malloc`'ed, I populated both of these maps and then eventually displayed the results. In order to test whether or not the invalid pointer is allocated within a different block, I looped through all the pointer in a single map and compared it to the pointer currently being freed. If that pointer being freed was within the bounds of any pointer in the map we were looping over, then I printed out that it was located in a different block.


## Collaborators:
Aaron Wang, Andrew Yang, Sohum Sanu

## Extra Credit attempted:
No

## How long did it take to complete DMalloc?
~18 hours

<!-- Enter an approximate number of hours that you spent actively working on the project. -->
