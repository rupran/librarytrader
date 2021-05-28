# librarytrader

[![pipeline status](https://gitlab.cs.fau.de/ziegler/librarytrader/badges/master/pipeline.svg)](https://gitlab.cs.fau.de/ziegler/librarytrader/commits/master)

A library to gather imports and exports of ELF shared libraries

## Prerequisites
- Python 3
- pyelftools, available from **pip** or at https://github.com/eliben/pyelftools
- capstone, available from **pip** or at https://github.com/aquynh/capstone
- pylibdebuginfod, available from **pip** or at https://github.com/rupran/pylibdebuginfod

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
**librarytrader** for analyzing a running system. It also has command line
flags for all the different aspects described below.

```
usage: running_analysis.py [-h] [-v] [-l LOAD] [-s STORE] [-r] [-i] [-t] [-a]
                           [-e ENTRY_LIST] [-u USED_FUNCTIONS] [--single]
                           [--uprobe-strings]
                           [paths [paths ...]]

Evaluate imports and exports of .so libraries and ELF executables.

positional arguments:
  paths                 the paths to process

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose output
  -l LOAD, --load LOAD  JSON file to load previously exported mapping
  -s STORE, --store STORE
                        Store calculated mapping to JSON file
  -r, --resolve-functions
                        Resolve imported functions to their origin
  -i, --interface_calls
                        Calculate calls between interface functions
  -t, --transitive-users
                        Propagate users over interface calls (implies -r)
  -a, --all-entries     Use all libraries as entry points for function
                        resolution. Default: only executables
  -e ENTRY_LIST, --entry-list ENTRY_LIST
                        Use paths inside the given file as entry points
                        regardless of their executable status
  -u USED_FUNCTIONS, --used-functions USED_FUNCTIONS
                        A file with path:name tuples which are referenced
                        symbols from dlsym
  --single              Do not recursively resolve libraries
  --uprobe-strings      Generate uprobe strings into a file
```

The resolution of imports on a live system is encapsulated in the `LibraryStore`
class. This class can be used as a dictionary to look up the `Library` objects
which have already been evaluated (by their absolute path). This mechanism also
serves as a cache during the recursive descent in order to avoid multiple
evaluation passes over frequently included libraries (such als `libc.so.6`).

As the resolution of a live system needs additional information from ldconfig
about the locations of libraries in your system, `LibraryStore` uses an instance
of `LDResolve` which parses the output of `ldconfig -p` and can be queried for
the possible paths for a given library name.

### Resolving library dependencies

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

### Storing/loading LibraryStore objects

You can use the `dump` method to export the current state of a `LibraryStore`
into a JSON file with a given filename, and the `load` method to fill an
existing `LibraryStore` from previously exported data. Note that `load`ing
currently clears any content the `LibraryStore` might hold.

### Resolving functions from libraries

After evaluating or loading the dependency tree, calling
`resolve_functions(elf)` on `LibraryStore` will (try to) resolve all imported
functions to the absolute paths of the libraries which provide the functions as
well as marking the importer as a user in the providing library.
After the resolution has finished, every function in the `imports` dictionary
is mapped to the absolute path of the library where the function is located.
`resolve_functions` can also be called with an absolute path to a library, in
which case it will internally try to resolve this path to a `Library` object in
the `LibraryStore`.

If you want to resolve all functions in all entries in the `LibraryStore`
object, you can call `resolve_all_functions()`. This function takes an optional
parameter `all_entries`, defaulting to `False`. If set to `True`, the
resolution will start from every known `Library` object in the store; if set to
`False`, only executable objects and their reachable dependencies will be
resolved.  If some files should be added to the resolution regardless of their
executable status, they can be added to an entry point list using the
`set_additional_entry_points()` method.

### Analyzing calls between exported functions

As exports might not only be referenced externally but also be called from
another exported function, we also need to consider calls between exports in
order to properly determine the set of used functions in libraries.

In the `interface_calls` module, the `resolve_calls` method starts a parallel
analysis of all `Library` objects, looking for calls to known exported
functions (either directly or via the PLT) in the disassembled binary code.
Disassembly is generated using the [Capstone](https://www.capstone-engine.org/)
framework.  The analysis populates the `calls` dictionary in the respective
`Library` object, with a function name as the key and a set of directly called
functions from that key as value.

This information is used by the `propagate_call_usage` method in `LibraryStore`
which propagates the external usage information calculated by
`resolve_functions()` into the functions which are called inside the same
library.

### Generating uprobe events

This tool can only do static analysis of binaries and libraries. For a more
detailed and fine-grained picture of the use of functions in a given system, we
might need dynamic tracing data to see which functions are actually used.

Linux provides
[uprobes](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html), an
event tracing interface which allows us to log executions of code at an offset
inside an executable file. As the `Library` objects already provide which
exports a given library has, we can generate uprobe events for every exported
function in order to get an output line in the trace file whenever the function
is called.

You can call `generate_uprobe_strings(output_name)` on `LibraryStore` which
will write a list of uprobe event strings into the file named `output_name`.
These events can then be written into the `uprobe_events` file in the tracing
filesystem of Linux. Note that the optional `all_entries` parameter defaults
to `True` for this function as the static analysis might have missed some
connections which the dynamic analysis then might discover.

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
