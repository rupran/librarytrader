# librarytrader
A library to gather imports and exports of ELF shared libraries

## Prerequisites
- Python 3
- pyelftools, available from **pip** or at https://github.com/eliben/pyelftools

## How to use it?
The `main.py` file offers a good example on how to use **librarytrader**.

First, create a `Library` object for the executable or shared object you want to analyze
by calling the constructor with an absolute path to the file in question, e.g. 
`elf = Library('/usr/lib/libsublime.so.8.0.0')`.

As the resolution needs some more information from the linker, it is encapsuled
in the `LibraryArchive` class. This class can also be used as a dictionary to look up the `Library`
objects which have already been evaluated (by their absolute path). This mechanism also
serves as a cache during the recursive descent in order to avoid multiple evalutations
of frequently included libraries (such als `libc.so.6`).

To resolve the dependencies to their full path without recursing into them, call
`resolve_libs_single(elf)`. After that, `elf.needed_libs` has been populated with
the absolute paths to all required libraries but these have not been analyzed for
imported or exported functions. Alternatively, you can call `resolve_libs_single_by_path(path)`
with an absolute path, and access the `Library` object later from the `LibraryArchive`.

To resolve the full dependency tree starting from `elf` you can call 
`resolve_libs_recursive(elf)`. This will traverse the dependencies in a depth-first
order, create `Library` objects for every library encountered, evaluate them and store their
imported and exported function names as keys in the `undefs` and `exported_functions`
member dictionaries, respectively. Again, there is a `resolve_libs_recursive_by_path(path)`
if you do not want to create and pass a `Library` object yourself but rather access that
information from the `LibraryArchive` later.

After evaluating the dependency tree, calling `resolve_functions(elf)` on `LibraryArchive`
will (try to) resolve all imported functions to the absolute paths of the library which
provides the functions. The mapping is returned as an `OrderedDict`.
