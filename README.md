# EDR Internals

Tools for analyzing EDR agents. For details, see our [blog post]().

* ESDump - macOS [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) client that dumps events to `stdout`
* NEDump - macOS [content filter provider](https://developer.apple.com/documentation/networkextension/content_filter_providers) that dumps socket flow data to `stdout`
* attacks/phantom_v1 - A collection of POCs that bypass different Linux syscalls using the [Phantom V1](https://github.com/rexguowork/phantom-attack/tree/main/phantom_v1) TOCTOU vulnerability
* dump_ebpf.sh - Linux [eBPF](https://ebpf.io/what-is-ebpf/) program and map enumeration script
* hook.py - [Frida](https://frida.re/) loader with [scripts](frida_scripts/) for inspecting key macOS monitoring functions

## Usage

* ESDump and NEDump can be compiled on macOS using [CMakeLists.txt](CMakeLists.txt) or you can download a precompiled [release](https://github.com/outflanknl/edr-internals/releases).
    * SIP must be [disabled](https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection) on the host for ESDump to work.
    * The NEDump app bundle must be copied to `/Applications/` to work.
* Any of the phantom_v1 can be compiled on Linux using the [Makefile](phantom_v1/Makefile).
* To use dump_ebpf.sh, [bpftool](https://github.com/libbpf/bpftool) must be installed.
* The [frida](https://pypi.org/project/frida/) Python package is required by hook.py.

## Credits

* NEDump is based on [LuLu](https://github.com/objective-see/LuLu) from [Objective-See](https://objective-see.org/)
* [Phantom V1](https://github.com/rexguowork/phantom-attack/tree/main/phantom_v1) was created by [Rex Guo](https://twitter.com/xiaofei_rex) and [Junyuan Zeng](https://scholar.google.com.au/citations?user=hfFxWxMAAAAJ) for [DEF CON 29](https://www.youtube.com/watch?v=yaAdM8pWKG8). 
