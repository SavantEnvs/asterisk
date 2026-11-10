#!/usr/bin/env bash
#
# mayhem/build.sh: build the Asterisk fuzz harnesses, their standalone reproducers and the selftest.
#
# Asterisk is a daemon with no library target, so the harnesses link the compiled core objects
# (main/*.o) directly, with asterisk.o's `main` renamed away. The tree is built twice with the
# project's own build system: first with normal flags (for mayhem/selftest.c, run by test.sh), then,
# after `make clean`, with $SANITIZER_FLAGS for the fuzz targets.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/out"
H="$SRC/mayhem/harnesses"
OOH="$SRC/addons/ooh323c/src"
rm -rf "$OUT"
mkdir -p "$OUT"

LIBS="-lxml2 -lxslt -lsqlite3 -lpthread -lssl -lcrypto -ljansson -luuid -lcrypt -lBlocksRuntime -lrt -ldl -lcap -lm -lresolv -ledit"
# Defines every Asterisk source needs; the harnesses and extra sources are not loadable modules.
COMMON="-fblocks -pthread -I$SRC/include -I/usr/include/libxml2 -DAST_MODULE=\"fuzz\" -DAST_MODULE_SELF_SYM=__internal_fuzz_self"
IAX_INC="-I$SRC/channels"
OOH_INC="-I$OOH -I$OOH/h323"

run_make() { env -u CFLAGS -u LDFLAGS -u CPPFLAGS make "$@"; }

configure_tree() {
  env -u CFLAGS -u LDFLAGS -u CPPFLAGS ./configure CC="$CC" CXX="$CXX" \
    --with-jansson-bundled=no --disable-xmldoc --without-pjproject
  [ -f menuselect.makeopts ] || run_make menuselect.makeopts
  # BUILD_NATIVE adds -march=native, which would make the image CPU-specific.
  menuselect/menuselect --disable BUILD_NATIVE menuselect.makeopts
}

main_objs() { ls "$SRC"/main/*.o "$SRC"/main/stdtime/localtime.o | grep -v '/asterisk\.o$'; }

# asterisk.o with `main` renamed so the harness drivers can supply their own.
make_nomain() { objcopy --redefine-sym main=asterisk_real_main "$SRC/main/asterisk.o" "$1"; }

# Compile one source into $2 with flags $3.. (shared by every group below).
cc_obj() { local src="$1" dst="$2"; shift 2; "$CC" "$@" $COMMON -c "$src" -o "$dst"; }

# Sources the harnesses and the selftest share, compiled into directory $1 with flags $2.
build_extras() {
  local dir="$1" flags="$2" f
  mkdir -p "$dir/iax" "$dir/ooh"
  # parser.c reads multi-byte IE values through casts of unaligned buffer pointers.
  cc_obj "$SRC/channels/iax2/parser.c" "$dir/iax/parser.o" $flags $IAX_INC -fno-sanitize=alignment
  cc_obj "$SRC/channels/iax2/codec_pref.c" "$dir/iax/codec_pref.o" $flags $IAX_INC
  cc_obj "$SRC/channels/iax2/format_compatibility.c" "$dir/iax/format_compatibility.o" $flags $IAX_INC
  cc_obj "$H/iax2_stubs.c" "$dir/iax/iax2_stubs.o" $flags $IAX_INC
  # The H.323 stack's PER decoder does unaligned loads.
  for f in "$OOH"/*.c "$OOH"/h323/*.c; do
    cc_obj "$f" "$dir/ooh/$(basename "$f" .c).o" $flags $OOH_INC -fno-sanitize=alignment
  done
}

# --- 1) normal-flags build: the selftest that mayhem/test.sh runs -------------------------------
configure_tree
run_make clean
run_make main -j"$MAYHEM_JOBS" ASTCFLAGS="$COVERAGE_FLAGS"
NF="-O1 -g $COVERAGE_FLAGS"
mkdir -p "$OUT/normal"
build_extras "$OUT/normal" "$NF"
cc_obj "$SRC/mayhem/selftest.c" "$OUT/normal/selftest.o" $NF $IAX_INC $OOH_INC
make_nomain "$OUT/normal/asterisk_nomain.o"
"$CC" $NF -pthread "$OUT/normal/selftest.o" "$OUT"/normal/iax/*.o "$OUT"/normal/ooh/*.o \
  $(main_objs) "$OUT/normal/asterisk_nomain.o" $LIBS $COVERAGE_FLAGS -o "$OUT/asterisk_selftest"

# --- 2) sanitized build: the fuzz targets --------------------------------------------------------
run_make clean
# fuzzer-no-link adds SanCov edge counters to the fuzzed code; -shared-libsan is only for the
# daemon link make performs (its binary is unused), which otherwise lacks the fuzzer runtime.
# DEBUG overrides the Makefile's -g3 (DWARF 5 under clang); pointer-overflow is relaxed because
# Asterisk's string helpers form `end = str + strlen(str) - 1` on empty strings.
SAN_ASTCFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -fno-sanitize=pointer-overflow"
if ! run_make main -j"$MAYHEM_JOBS" DEBUG="$DEBUG_FLAGS" ASTCFLAGS="$SAN_ASTCFLAGS" \
      ASTLDFLAGS="$SANITIZER_FLAGS -shared-libsan"; then
  # Without a sanitizer runtime (SANITIZER_FLAGS empty) only the daemon link fails, and the daemon
  # is unused: all that matters is that the objects were built.
  [ -z "$SANITIZER_FLAGS" ] && [ "$(ls "$SRC"/main/*.o | wc -l)" -ge 150 ] || exit 1
fi

SF="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -fno-sanitize=pointer-overflow -O1"
mkdir -p "$OUT/san"
build_extras "$OUT/san" "$SF"
make_nomain "$OUT/san/asterisk_nomain.o"
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/san/lsan_off.o"
# Weak no-op SanCov hooks for the standalone reproducers when no sanitizer runtime provides them.
cat > "$OUT/san/sancov_stubs.c" <<'EOF'
#include <stdint.h>
#define W __attribute__((weak))
W void __sanitizer_cov_8bit_counters_init(char *s, char *e) { (void)s; (void)e; }
W void __sanitizer_cov_pcs_init(const uintptr_t *s, const uintptr_t *e) { (void)s; (void)e; }
W void __sanitizer_cov_trace_pc_indir(uintptr_t c) { (void)c; }
W void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_switch(uint64_t v, uint64_t *c) { (void)v; (void)c; }
EOF
"$CC" -O1 -c "$OUT/san/sancov_stubs.c" -o "$OUT/san/sancov_stubs.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/san/standalone_main.o"

IAX_OBJS=( "$OUT"/san/iax/*.o )
OOH_OBJS=( "$OUT"/san/ooh/*.o )
MAIN_OBJS=( $(main_objs) )

# link_target <name> <extra objects...>: the libFuzzer binary and the standalone reproducer.
link_target() {
  local name="$1"; shift
  cc_obj "$H/$name.c" "$OUT/san/$name.o" $SF $IAX_INC $OOH_INC
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -pthread $LIB_FUZZING_ENGINE "$OUT/san/$name.o" "$@" \
    "$OUT/san/lsan_off.o" "${MAIN_OBJS[@]}" "$OUT/san/asterisk_nomain.o" $LIBS -o "/mayhem/$name"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -pthread "$OUT/san/standalone_main.o" "$OUT/san/$name.o" "$@" \
    "$OUT/san/lsan_off.o" "$OUT/san/sancov_stubs.o" "${MAIN_OBJS[@]}" "$OUT/san/asterisk_nomain.o" $LIBS \
    -o "/mayhem/$name-standalone"
}

link_target fuzz_expr
link_target fuzz_stun
link_target fuzz_dns_rr
link_target fuzz_config
link_target fuzz_utils
link_target fuzz_base64
link_target fuzz_iax2_ies "${IAX_OBJS[@]}"
link_target fuzz_h323 "${OOH_OBJS[@]}"
