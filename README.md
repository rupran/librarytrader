# librarytrader
A library to gather imports and exports of ELF shared libraries

## Prerequisites
- Python 3
- pyelftools, available from **pip** or at https://github.com/eliben/pyelftools

## How to use it?
The `main.py` file offers a good example on how to use **librarytrader**.

`Library` objects are used to store the relevant information from the ELF files,
such as unresolved functions from other libraries (let's call them imports) and
global functions which can be called from other modules (exports).

You may create a `Library` object for the executable or shared object you want
to analyze by calling its constructor with an absolute path to the file in
question, e.g.  `elf = Library('/usr/lib/libsublime.so.8.0.0')`. This will parse
the ELF header and create an underlying `ELFFile` object provided by
**pyelftools** but does not automatically resolve imports and exports.

As the resolution needs some more information from the linker, it is
encapsulated in the `LibraryStore` class. This class can be used as a
dictionary to look up the `Library` objects which have already been evaluated
(by their absolute path). This mechanism also serves as a cache during the
recursive descent in order to avoid multiple evaluation passes over frequently
included libraries (such als `libc.so.6`).

To resolve the dependencies to their full path without recursing into them,
call `resolve_libs_single(elf)`. After that, `elf.needed_libs` has been
populated with the absolute paths to all required libraries but these have not
been analyzed for imported or exported functions. Alternatively, you can call
`resolve_libs_single_by_path(path)` with an absolute path, and access the
`Library` object later from the `LibraryStore` by using its path as a key.

To resolve the full dependency tree starting from `elf` you can call
`resolve_libs_recursive(elf)`. This will traverse the dependencies in a
depth-first order, create and populate `Library` objects for every library
encountered and store their imported and exported function names as keys in the
`imports` and `exports` member dictionaries, respectively. Again, there is a
`resolve_libs_recursive_by_path(path)` if you do not want to create and pass a
`Library` object yourself but rather access that information from the
`LibraryStore` later.

You can use the `dump` method to export the current state of a `LibraryStore`
into a JSON file with a given filename, and the `load` method to fill an
existing `LibraryStore` from previously exported data. Note that `load`ing
currently clears any content the `LibraryStore` might hold.

After evaluating or loading the dependency tree, calling
`resolve_functions(elf)` on `LibraryStore` will (try to) resolve all imported
functions to the absolute paths of the libraries which provide the functions.
The mapping is returned as an `OrderedDict`. `resolve_functions` can also be
called with an absolute path to a library, in which case it will internally
try to resolve this path to a `Library` object in the `LibraryStore`.
