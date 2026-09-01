const std = @import("std");

const WolfsslMode = enum {
    /// Build wolfSSL from the Zig package dependency and link the resulting
    /// static archive into the executable. On native Unix-like hosts this uses
    /// autotools (sh/configure/make); on Windows -- native or cross -- it uses
    /// CMake with Zig's own C compiler (`zig cc`), so no MSVC/MinGW install is
    /// required. This is the default everywhere.
    bundled,
    /// Use an already-built wolfSSL prefix passed with -Dwolfssl-prefix=PATH.
    system,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Default to ReleaseSafe rather than Zig's usual Debug default.
    //
    // This matters more than it looks. The ironwood control plane signs an
    // Ed25519 response for every sigReq, and the sigReq/sigRes round trip is
    // what `getPeers` reports as `latency` and what `Router.getCost` turns into
    // the parent-selection cost. In Debug, std.crypto's Ed25519 signature costs
    // ~2.3 ms against ~59 us optimized -- a 40x penalty that showed up directly
    // as inflated latency and cost, and would distort routing on a real mesh.
    // ReleaseSafe keeps the safety checks (this daemon parses untrusted network
    // input) while compiling the crypto and hot paths properly.
    //
    // Note this is a real `-Doptimize` option, not `standardOptimizeOption`'s
    // `preferred_optimize_mode`: that one only changes what `-Drelease` maps to
    // and still leaves the default at Debug, which is exactly the footgun that
    // produced the numbers above.
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size (default: ReleaseSafe)",
    ) orelse .ReleaseSafe;

    // Tests default to Debug so `zig build test` keeps every safety check and
    // catches undefined behaviour that ReleaseSafe would also catch but
    // ReleaseFast/Small would not. Override with -Dtest-optimize=... to run the
    // suite in the same mode you ship.
    const test_optimize = b.option(
        std.builtin.OptimizeMode,
        "test-optimize",
        "Optimization mode for the test binaries (default: Debug)",
    ) orelse .Debug;

    const wolfssl_mode = b.option(WolfsslMode, "wolfssl", "WolfSSL source: bundled (default) or system") orelse .bundled;
    const wolfssl_prefix = b.option([]const u8, "wolfssl-prefix", "Path to a WolfSSL install prefix containing include/ and lib/libwolfssl.a");

    // ---- dependencies -----------------------------------------------------
    const libxev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });
    const xev_mod = libxev.module("xev");

    // ---- shared utilities -------------
    const util_mod = b.addModule("util", .{
        .root_source_file = b.path("src/util/util.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ---- async runtime module (libxev) ------------------------------------
    const async_mod = b.addModule("async", .{
        .root_source_file = b.path("src/async/async.zig"),
        .target = target,
        .optimize = optimize,
    });
    async_mod.addImport("xev", xev_mod);

    // ---- ironwood module --------------------------------------------------
    const ironwood = b.addModule("ironwood", .{
        .root_source_file = b.path("src/ironwood/ironwood.zig"),
        .target = target,
        .optimize = optimize,
    });
    ironwood.addImport("xev", xev_mod);
    ironwood.addImport("async", async_mod);
    ironwood.addImport("util", util_mod);

    // ---- node module ------------------------------------------------------
    const node_mod = b.addModule("node", .{
        .root_source_file = b.path("src/node/node.zig"),
        .target = target,
        .optimize = optimize,
    });
    node_mod.addImport("ironwood", ironwood);
    node_mod.addImport("xev", xev_mod);
    node_mod.addImport("async", async_mod);
    node_mod.addImport("util", util_mod);

    const zquic_dep = b.dependency("zquic", .{
        .target = target,
        .optimize = optimize,
    });
    const zquic_mod = zquic_dep.module("zquic");
    node_mod.addImport("zquic", zquic_mod);

    const wolfssl = configureWolfssl(b, target, wolfssl_mode, wolfssl_prefix);
    const lws = configureLibwebsockets(b, target, wolfssl.build_step);

    // ---- yggdrasil executable ---------------------------------------------
    const exe = b.addExecutable(.{
        .name = "yggdrasil",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("ironwood", ironwood);
    exe.root_module.addImport("xev", xev_mod);
    exe.root_module.addImport("async", async_mod);
    exe.root_module.addImport("node", node_mod);
    linkWolfssl(exe.root_module, wolfssl);
    linkLibwebsockets(exe.root_module, lws);

    b.installArtifact(exe);

    if (target.result.os.tag == .windows) {
        if (wintunDllPath(b, target)) |dll| {
            const install_dll = b.addInstallBinFile(dll, "wintun.dll");
            b.getInstallStep().dependOn(&install_dll.step);
        }
    }

    // ---- peer_probe tool --------------------------------------------------
    const probe = b.addExecutable(.{
        .name = "peer_probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/peer_probe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    probe.root_module.addImport("ironwood", ironwood);
    probe.root_module.addImport("node", node_mod);
    probe.root_module.addImport("util", util_mod);
    linkWolfssl(probe.root_module, wolfssl);
    linkLibwebsockets(probe.root_module, lws);

    b.installArtifact(probe);

    // ---- steps ------------------------------------------------------------
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the yggdrasil node");
    run_step.dependOn(&run_cmd.step);

    const probe_cmd = b.addRunArtifact(probe);
    probe_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| probe_cmd.addArgs(args);
    const probe_step = b.step("probe", "Probe a peer");
    probe_step.dependOn(&probe_cmd.step);

    // ---- tests ------------------------------------------------------------
    const test_step = b.step("test", "Run unit tests");

    const ironwood_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ironwood/ironwood.zig"),
            .target = target,
            .optimize = test_optimize,
        }),
    });
    ironwood_tests.root_module.addImport("xev", xev_mod);
    ironwood_tests.root_module.addImport("async", async_mod);
    ironwood_tests.root_module.addImport("util", util_mod);
    const run_ironwood_tests = b.addRunArtifact(ironwood_tests);
    test_step.dependOn(&run_ironwood_tests.step);

    const util_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/util/util.zig"),
            .target = target,
            .optimize = test_optimize,
        }),
    });
    const run_util_tests = b.addRunArtifact(util_tests);
    test_step.dependOn(&run_util_tests.step);

    const async_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/async/async.zig"),
            .target = target,
            .optimize = test_optimize,
        }),
    });
    async_tests.root_module.addImport("xev", xev_mod);
    const run_async_tests = b.addRunArtifact(async_tests);
    test_step.dependOn(&run_async_tests.step);

    const node_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/node/node.zig"),
            .target = target,
            .optimize = test_optimize,
        }),
    });
    node_tests.root_module.addImport("ironwood", ironwood);
    node_tests.root_module.addImport("xev", xev_mod);
    node_tests.root_module.addImport("async", async_mod);
    node_tests.root_module.addImport("util", util_mod);
    node_tests.root_module.addImport("zquic", zquic_mod);
    linkWolfssl(node_tests.root_module, wolfssl);
    linkLibwebsockets(node_tests.root_module, lws);
    const run_node_tests = b.addRunArtifact(node_tests);
    test_step.dependOn(&run_node_tests.step);
}

const WolfsslPaths = struct {
    include_dir: std.Build.LazyPath,
    static_lib: std.Build.LazyPath,
    /// The step that produces the archive, so other C dependency builds can be
    /// ordered after it. Null when a prebuilt -Dwolfssl-prefix is in use.
    build_step: ?*std.Build.Step = null,
};

fn targetIsWindows(target: std.Build.ResolvedTarget) bool {
    return target.result.os.tag == .windows;
}

/// True when the requested target differs from the build host (in a way that
/// matters for the C dependency builds: OS or CPU architecture).
fn isCross(b: *std.Build, target: std.Build.ResolvedTarget) bool {
    const host = b.graph.host.result;
    return target.result.os.tag != host.os.tag or
        target.result.cpu.arch != host.cpu.arch;
}

/// The `-target` triple to pass to `zig cc` when cross-compiling, or null for
/// native builds. The C dependency scripts generate their own `zig cc` wrapper
/// (with the executable bit set and a full path) from this.
fn zigTargetTriple(b: *std.Build, target: std.Build.ResolvedTarget) ?[]const u8 {
    if (!isCross(b, target)) return null;
    return target.result.zigTriple(b.graph.arena) catch @panic("OOM");
}

fn configureWolfssl(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    mode: WolfsslMode,
    prefix: ?[]const u8,
) WolfsslPaths {
    if (prefix) |p| {
        return .{
            .include_dir = .{ .cwd_relative = b.pathJoin(&.{ p, "include" }) },
            .static_lib = .{ .cwd_relative = b.pathJoin(&.{ p, "lib", "libwolfssl.a" }) },
        };
    }

    switch (mode) {
        .system => @panic("-Dwolfssl=system requires -Dwolfssl-prefix=/path/to/wolfssl/install"),
        .bundled => {},
    }

    const wolfssl_dep = b.dependency("wolfssl", .{});

    // Windows (native or cross): CMake + zig cc. Works with just Zig + CMake
    // installed -- no MSVC, MinGW, autoconf or libtool needed.
    if (targetIsWindows(target)) {
        return configureWolfsslCmake(b, target, wolfssl_dep.path("."));
    }

    // Cross-compiling to a non-Windows OS (e.g. macOS from Linux) needs that
    // OS's SDK; autotools cannot cross here, so require an explicit prefix.
    if (isCross(b, target)) {
        @panic("bundled wolfSSL cross-compiles to Windows via CMake/zig cc; for other cross targets pass -Dwolfssl=system -Dwolfssl-prefix=/path/to/target/wolfssl");
    }

    // Native Unix-like build: autotools, as before.
    switch (target.result.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos => {},
        else => @panic("bundled wolfSSL requires a Unix-like build host with sh, make, autoconf and libtool; pass -Dwolfssl-prefix for this target"),
    }

    const run = b.addSystemCommand(&.{
        "sh",
        "-c",
        \\set -eu
        \\src="$1"
        \\out="$2"
        \\rm -rf "$out"
        \\mkdir -p "$out"
        \\cp -R "$src" "$out/src"
        \\cd "$out/src"
        \\chmod +x ./autogen.sh ./configure 2>/dev/null || true
        \\if [ ! -f ./configure ]; then
        \\  sh ./autogen.sh
        \\fi
        \\sh ./configure \
        \\  --prefix="$out/install" \
        \\  --enable-static \
        \\  --disable-shared \
        \\  --enable-tls13 \
        \\  --enable-sni \
        \\  --enable-quic \
        \\  --enable-opensslextra \
        \\  --enable-ed25519 \
        \\  --enable-curve25519 \
        \\  --enable-certgen \
        \\  --enable-keygen \
        \\  --enable-altcertchains
        \\make -j${NPROC:-2}
        \\make install
        \\test -f "$out/install/lib/libwolfssl.a"
        ,
        "build-wolfssl",
    });
    run.addDirectoryArg(wolfssl_dep.path("."));
    const out_dir = run.addOutputDirectoryArg("wolfssl");

    return .{
        .include_dir = out_dir.path(b, "install/include"),
        .static_lib = out_dir.path(b, "install/lib/libwolfssl.a"),
        .build_step = &run.step,
    };
}

/// wolfSSL via CMake + `zig cc`. Used for Windows builds (native and cross).
fn configureWolfsslCmake(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    wolfssl_src: std.Build.LazyPath,
) WolfsslPaths {
    const run = b.addSystemCommand(&.{
        "sh",
        "-c",
        \\set -eu
        \\src="$1"
        \\out="$2"
        \\zigexe="$3"
        \\triple="$4"
        \\shift 4
        \\rm -rf "$out"
        \\mkdir -p "$out"
        \\if [ -n "$triple" ]; then
        \\  printf '#!/bin/sh\nexec "%s" cc -target "%s" "$@"\n' "$zigexe" "$triple" > "$out/zig-cc.sh"
        \\else
        \\  printf '#!/bin/sh\nexec "%s" cc "$@"\n' "$zigexe" > "$out/zig-cc.sh"
        \\fi
        \\chmod +x "$out/zig-cc.sh"
        \\cmake -S "$src" -B "$out/build" \
        \\  "-DCMAKE_C_COMPILER=$out/zig-cc.sh" \
        \\  "$@" \
        \\  "-DCMAKE_INSTALL_PREFIX=$out/install" \
        \\  -DCMAKE_BUILD_TYPE=Release \
        \\  -DCMAKE_C_FLAGS=-Wno-error=date-time \
        \\  -DBUILD_SHARED_LIBS=OFF \
        \\  -DWOLFSSL_TLS13=yes \
        \\  -DWOLFSSL_QUIC=yes \
        \\  -DWOLFSSL_OPENSSLEXTRA=yes \
        \\  -DWOLFSSL_SNI=yes \
        \\  -DWOLFSSL_OPENSSLALL=yes \
        \\  -DWOLFSSL_ED25519=yes \
        \\  -DWOLFSSL_CURVE25519=yes \
        \\  -DWOLFSSL_CERTGEN=yes \
        \\  -DWOLFSSL_KEYGEN=yes
        \\cmake --build "$out/build" -j"${NPROC:-2}"
        \\cmake --install "$out/build"
        \\test -f "$out/install/lib/libwolfssl.a"
        ,
        "build-wolfssl-cmake",
    });
    run.addDirectoryArg(wolfssl_src);
    const out_dir = run.addOutputDirectoryArg("wolfssl");
    run.addArg(b.graph.zig_exe);
    run.addArg(zigTargetTriple(b, target) orelse "");
    if (isCross(b, target)) {
        run.addArg("-DCMAKE_SYSTEM_NAME=Windows");
        run.addArg("-DCMAKE_SYSTEM_PROCESSOR=x86_64");
    }

    return .{
        .include_dir = out_dir.path(b, "install/include"),
        .static_lib = out_dir.path(b, "install/lib/libwolfssl.a"),
        .build_step = &run.step,
    };
}

fn linkWolfssl(module: *std.Build.Module, wolfssl: WolfsslPaths) void {
    module.addIncludePath(wolfssl.include_dir);
    // Add the archive by path instead of `-lwolfssl`, so the result is linked
    // statically even on systems that also have a shared libwolfssl installed.
    module.addObjectFile(wolfssl.static_lib);
    module.link_libc = true;
    const target = module.resolved_target orelse @panic("linkWolfssl requires a module with a resolved target");
    switch (target.result.os.tag) {
        .windows => {
            // wolfSSL's default build enables loading system CA certs, which on
            // Windows goes through the Crypt32 certificate-store APIs
            // (CertOpenSystemStoreA/CertEnumCertificatesInStore/CertCloseStore).
            module.linkSystemLibrary("crypt32", .{});
            module.linkSystemLibrary("ws2_32", .{});
            module.linkSystemLibrary("iphlpapi", .{});
        },
        .linux => {
            module.linkSystemLibrary("m", .{});
            module.linkSystemLibrary("pthread", .{});
        },
        // macOS, *BSD, etc.: libSystem/libc already provide libm and pthread.
        else => {},
    }
}

const LwsPaths = struct {
    include_dir: std.Build.LazyPath,
    static_lib: std.Build.LazyPath,
};

/// `after`, when non-null, is another C dependency's build step. wolfSSL and
/// libwebsockets are both large C builds and Zig would otherwise run them
/// concurrently; on a small machine (2 GB RAM) that gets them both killed by
/// the OOM killer partway through, which looks like a mysterious build failure
/// with no compiler error in the log. Serializing them costs a little wall time
/// on big machines and makes the build actually finish on small ones.
fn configureLibwebsockets(b: *std.Build, target: std.Build.ResolvedTarget, after: ?*std.Build.Step) LwsPaths {
    const lws_dep = b.dependency("libwebsockets", .{});

    if (targetIsWindows(target)) {
        return configureLibwebsocketsCmake(b, target, lws_dep.path("."), after);
    }

    if (isCross(b, target)) {
        @panic("bundled libwebsockets cross-compiles to Windows via CMake/zig cc; for other cross targets build libwebsockets yourself and link it with -Dlws-prefix");
    }

    const run = b.addSystemCommand(&.{
        "sh",
        "-c",
        \\set -eu
        \\src="$1"
        \\out="$2"
        \\rm -rf "$out"
        \\mkdir -p "$out/build"
        \\cmake -S "$src" -B "$out/build" \
        \\  -DCMAKE_INSTALL_PREFIX="$out/install" \
        \\  -DCMAKE_BUILD_TYPE=Release \
        \\  -DCMAKE_C_FLAGS="-Wno-error -Wno-unused-label" \
        \\  -DLWS_WITH_SSL=OFF \
        \\  -DLWS_WITH_SHARED=OFF \
        \\  -DLWS_WITH_STATIC=ON \
        \\  -DLWS_WITHOUT_TESTAPPS=ON \
        \\  -DLWS_WITHOUT_TEST_SERVER=ON \
        \\  -DLWS_WITHOUT_TEST_CLIENT=ON \
        \\  -DLWS_WITHOUT_TEST_PING=ON \
        \\  -DLWS_WITHOUT_TEST_ECHO=ON \
        \\  -DLWS_WITH_MINIMAL_EXAMPLES=OFF \
        \\  -DLWS_WITH_HTTP2=OFF \
        \\  -DLWS_IPV6=ON
        \\cmake --build "$out/build" -j"${NPROC:-2}"
        \\cmake --install "$out/build"
        \\if [ -f "$out/install/lib64/libwebsockets.a" ] && [ ! -f "$out/install/lib/libwebsockets.a" ]; then
        \\  mkdir -p "$out/install/lib"
        \\  cp "$out/install/lib64/libwebsockets.a" "$out/install/lib/"
        \\fi
        \\test -f "$out/install/lib/libwebsockets.a"
        ,
        "build-libwebsockets",
    });
    if (after) |step| run.step.dependOn(step);
    run.addDirectoryArg(lws_dep.path("."));
    const out_dir = run.addOutputDirectoryArg("libwebsockets");
    return .{
        .include_dir = out_dir.path(b, "install/include"),
        .static_lib = out_dir.path(b, "install/lib/libwebsockets.a"),
    };
}

/// libwebsockets for Windows (native or cross): CMake + `zig cc`. lws's win32
/// port assumes a case-insensitive filesystem (`<Psapi.h>`) and gcc-style
/// warnings, so we provide a casing shim and downgrade the stricter clang
/// diagnostics that zig cc enables.
fn configureLibwebsocketsCmake(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lws_src: std.Build.LazyPath,
    after: ?*std.Build.Step,
) LwsPaths {
    const run = b.addSystemCommand(&.{
        "sh",
        "-c",
        \\set -eu
        \\src="$1"
        \\out="$2"
        \\zigexe="$3"
        \\triple="$4"
        \\shift 4
        \\rm -rf "$out"
        \\mkdir -p "$out"
        \\if [ -n "$triple" ]; then
        \\  printf '#!/bin/sh\nexec "%s" cc -target "%s" "$@"\n' "$zigexe" "$triple" > "$out/zig-cc.sh"
        \\else
        \\  printf '#!/bin/sh\nexec "%s" cc "$@"\n' "$zigexe" > "$out/zig-cc.sh"
        \\fi
        \\chmod +x "$out/zig-cc.sh"
        \\# lws includes <Psapi.h> but mingw ships psapi.h (lowercase); a shim
        \\# include dir fixes the case on case-sensitive filesystems.
        \\mkdir -p "$out/shim"
        \\printf '#ifndef PSAPI_H_ALIAS\n#define PSAPI_H_ALIAS\n#include <psapi.h>\n#endif\n' > "$out/shim/Psapi.h"
        \\cmake -S "$src" -B "$out/build" \
        \\  "-DCMAKE_C_COMPILER=$out/zig-cc.sh" \
        \\  "$@" \
        \\  "-DCMAKE_INSTALL_PREFIX=$out/install" \
        \\  -DCMAKE_BUILD_TYPE=Release \
        \\  "-DCMAKE_C_FLAGS=-I$out/shim -include pthread.h -Wno-error -Wno-unused-label -Wno-error=date-time -Wno-macro-redefined -Wno-error=int-conversion -Wno-error=incompatible-pointer-types" \
        \\  -DDISABLE_WERROR=ON \
        \\  -DLWS_HAVE_PTHREAD_H=1 \
        \\  -DLWS_WITH_SSL=OFF \
        \\  -DLWS_WITH_SCHANNEL=OFF \
        \\  -DLWS_WITH_SHARED=OFF \
        \\  -DLWS_WITH_STATIC=ON \
        \\  -DLWS_WITHOUT_TESTAPPS=ON \
        \\  -DLWS_WITHOUT_TEST_SERVER=ON \
        \\  -DLWS_WITHOUT_TEST_CLIENT=ON \
        \\  -DLWS_WITHOUT_TEST_PING=ON \
        \\  -DLWS_WITH_MINIMAL_EXAMPLES=OFF \
        \\  -DLWS_WITH_HTTP2=OFF \
        \\  -DLWS_IPV6=ON
        \\cmake --build "$out/build" -j"${NPROC:-2}"
        \\cmake --install "$out/build"
        \\# lws names its static archive libwebsockets_static.a on Windows.
        \\if [ -f "$out/install/lib/libwebsockets_static.a" ] && [ ! -f "$out/install/lib/libwebsockets.a" ]; then
        \\  cp "$out/install/lib/libwebsockets_static.a" "$out/install/lib/libwebsockets.a"
        \\fi
        \\test -f "$out/install/lib/libwebsockets.a"
        ,
        "build-libwebsockets-cmake",
    });
    if (after) |step| run.step.dependOn(step);
    run.addDirectoryArg(lws_src);
    const out_dir = run.addOutputDirectoryArg("libwebsockets");
    run.addArg(b.graph.zig_exe);
    run.addArg(zigTargetTriple(b, target) orelse "");
    if (isCross(b, target)) {
        run.addArg("-DCMAKE_SYSTEM_NAME=Windows");
        run.addArg("-DCMAKE_SYSTEM_PROCESSOR=x86_64");
    }

    return .{
        .include_dir = out_dir.path(b, "install/include"),
        .static_lib = out_dir.path(b, "install/lib/libwebsockets.a"),
    };
}

fn linkLibwebsockets(module: *std.Build.Module, lws: LwsPaths) void {
    module.addIncludePath(lws.include_dir);
    module.addObjectFile(lws.static_lib);
    module.link_libc = true;
    const target = module.resolved_target orelse @panic("linkLibwebsockets requires a module with a resolved target");
    switch (target.result.os.tag) {
        .windows => {
            // lws uses winsock, and we force pthreads on Windows (its win32
            // port otherwise has no mutex implementation).
            module.linkSystemLibrary("ws2_32", .{});
            module.linkSystemLibrary("pthread", .{});
        },
        else => {},
    }
}

/// Locate the architecture-appropriate `wintun.dll` inside the `wintun`
/// package dependency (see build.zig.zon), fetched lazily -- only Windows
/// builds pay for downloading it. Returns null if the dependency isn't
/// available (e.g. offline build without the package pre-fetched) so the
/// caller can skip installing it with a warning instead of hard-failing;
/// the resulting binary just won't find a TUN device at runtime without a
/// `wintun.dll` placed next to it by other means.
fn wintunDllPath(b: *std.Build, target: std.Build.ResolvedTarget) ?std.Build.LazyPath {
    const wintun_dep = b.lazyDependency("wintun", .{}) orelse return null;
    const arch_dir = switch (target.result.cpu.arch) {
        .x86_64 => "amd64",
        .x86 => "x86",
        .aarch64 => "arm64",
        .arm => "arm",
        else => {
            std.log.warn("no prebuilt wintun.dll for target arch {s}; TUN will be unavailable at runtime", .{@tagName(target.result.cpu.arch)});
            return null;
        },
    };
    return wintun_dep.path(b.pathJoin(&.{ "bin", arch_dir, "wintun.dll" }));
}
