/*
 * seekpos_stub.c: satisfy vtable reference in libduckdb.a (MinGW ABI mismatch).
 *
 * libduckdb.a needs seekpos(fpos<_Mbstateˮt>) but GCC 15 libstdc++ only exports
 * seekpos(fpos<int>). The symbol only lives in the vtable of data_sink_streambuf
 * (write-only HTTP sink), so seekpos is never actually invoked.
 *
 * Exact required mangled symbol (from nm --undefined-only libduckdb.a):
 *   _ZNSt15basic_streambufIcSt11char_traitsIcEE7seekposESt4fposI9_MbstatetESt13_Ios_Openmode
 *
 * Windows x86-64 member-function returning struct > 8 bytes (fpos = 16 bytes):
 *   RCX = hidden return pointer, RDX = this, R8 = fpos arg, R9 = openmode
 *   Return RAX = RCX. We write fpos{-1, 0} to signal failure (EOF).
 */
__asm__(
    ".text\n"
    ".global _ZNSt15basic_streambufIcSt11char_traitsIcEE7seekposESt4fposI9_MbstatetESt13_Ios_Openmode\n"
    "_ZNSt15basic_streambufIcSt11char_traitsIcEE7seekposESt4fposI9_MbstatetESt13_Ios_Openmode:\n"
    "movq $-1, (%rcx)\n"
    "movq $0,  8(%rcx)\n"
    "movq %rcx, %rax\n"
    "ret\n"
);
