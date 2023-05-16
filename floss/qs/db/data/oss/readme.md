# Strings from Open Source libraries

The following databases were extracted via the vkpkg & jh technique:

  - zlib 1.2.13


## The vkpkg & jh technique

Major steps:

  1. build static libraries via vcpkg
  2. extract features via jh
  3. convert to JSONL format with `jh_to_qs.py`
  4. compress with gzip

### Build static libraries via vcpkg

[vcpkg](https://vcpkg.io/en/) is a free C/C++ package manager for acquiring and managing libraries.
We use it to easily build common open source libraries, like zlib.
Use the triplet `x64-windows-static` to build static archives (.lib files that are AR archives containing COFF object files):

```console
PS > C:\vcpkg\vcpkg.exe install --triplet x64-windows-static zlib
```

### Extract features via jh

[jh](https://github.com/williballenthin/lancelot/blob/master/bin/src/bin/jh.rs)
is a lancelot-based utility that parses AR archives containing COFF object files,
reconstructs their control flow, finds functions, and extracts features. 
jh extracts numbers, API calls, and strings; we are only interested in the string features.

For each feature, jh emits a CSV line with the fields 
  - target triplet
  - compiler 
  - library
  - version
  - build profile
  - path
  - function
  - feature type
  - feature value

For example:

```csv
x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffCompress,number,0x00000100
```

For example, to invoke jh:

```console
$ ~/lancelot/target/release/jh x64-windows-static msvc143 zlib 1.2.13 release /mnt/c/vcpkg/installed/x64-windows-static/lib/zlib.lib > ~/flare-floss/floss/qs/db/data/oss/zlib.csv
```

### Convert to OSS database format

We use the script `jh_to_qs.py` to convert these CSV lines into JSONL file prepared for FLOSS:

```console
$ python3 jh_to_qs.py zlib.csv > zlib.jsonl
```

These files are then gzip'd:

```console
$  gzip -c zlib.jsonl > zlib.jsonl.gz
```
