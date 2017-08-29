# librarytrader
A library to gather imports and exports of ELF shared libraries

## Prerequisites
- Python 3
- pyelftools, available from **pip** or at https://github.com/eliben/pyelftools

## How to use it?

Relevant information from the ELF files, such as unresolved functions from other
libraries (let's call them imports) and global functions which can be called
from other modules (exports), is stored in `Library` objects.

You may create a `Library` object for the executable or shared object you want
to analyze by calling its constructor with an absolute path to the file in
question, e.g.  `elf = Library('/usr/lib/libsublime.so.8.0.0')`. This will parse
the ELF header and create an underlying `ELFFile` object provided by
**pyelftools** but does not automatically resolve imports and exports.

## Analyzing your currently running system

The script at `scripts/running_analysis.py` offers a good example on how to use
**librarytrader** for analyzing a running system.

The resolution of imports on a live system is encapsulated in the `LibraryStore`
class. This class can be used as a dictionary to look up the `Library` objects
which have already been evaluated (by their absolute path). This mechanism also
serves as a cache during the recursive descent in order to avoid multiple
evaluation passes over frequently included libraries (such als `libc.so.6`).

As the resolution of a live system needs additional information from ldconfig
about the locations of libraries in your system, `LibraryStore` uses an instance
of `LDResolve` which parses the output of `ldconfig -p` and can be queried for
the possible paths for a given library name.

To resolve the dependencies to their full path without recursing into them, call
`resolve_libs_single(elf)`. After that, `elf.needed_libs` has been populated
with the absolute paths to all required libraries but these have not been
analyzed for imported or exported functions. Alternatively, you can call
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
called with an absolute path to a library, in which case it will internally try
to resolve this path to a `Library` object in the `LibraryStore`.

## Analyzing a collection of object files

If you know the set of ELF files you would like to analyze but do not
have a running system, you can use the `DirectoryScan` class. This class only
requires a directory name containing all ELF files in question and will
try to cross-reference all imports and exports from the files contained in this
directory.

After constructing an object with `scan = DirectoryScan('./libdir/')`, you can
instruct `scan` to parse the ELF files by calling `read_libraries`. After that,
`scan.libraries` will contain a `Library` object for every ELF file in the base
directory. With this done, you can call the `try_resolve` method to
cross-reference all imports and exports between the `Library` objects.

Once `try_resolve` has been run, all `Library`'s `imports` and `exports`
dictionaries will contain values for referenced functions; for a successfully
resolved imported function, its value will be the path to the object file from
which the function is imported; on the other end, if a function is exported
and referenced from another file, its value will be a list of paths to all
object files importing the function in question.

This information can be printed using the `print_imports_exports` method. If you
only want to print import/export information for a subset of all files, this
method supports passing a `name_match` parameter: if given, only those libraries
are printed for which `name_match` is a substring of the target library name(s).

An example for using `DirectoryScan` can be found in
`scripts/directory_example.py`.
