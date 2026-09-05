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

    // ---- ctl module (control mode: one-shot admin client) ------------------
    // Sits outside `node` because it needs none of the router, but it does
    // share node's `unix://` policy so a `unix://` endpoint is refused on
    // Windows with the same message the node gives for `unix://` peers.
    const ctl_mod = b.addModule("ctl", .{
        .root_source_file = b.path("src/node/ctl.zig"),
        .target = target,
        .optimize = optimize,
    });
    ctl_mod.addImport("util", util_mod);
    ctl_mod.addImport("node", node_mod);

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
    exe.root_module.addImport("ctl", ctl_mod);
    exe.root_module.addImport("util", util_mod);
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

    const ctl_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/node/ctl.zig"),
            .target = target,
            .optimize = test_optimize,
        }),
    });
    ctl_tests.root_module.addImport("node", node_mod);
    const run_ctl_tests = b.addRunArtifact(ctl_tests);
    test_step.dependOn(&run_ctl_tests.step);
}

const WolfsslPaths = struct {
    include_dir: std.Build.LazyPath,
    static_lib: std.Build.LazyPath,
    /// The step that produces the archive, so other C dependency builds can be
    /// ordered after it. Null when a prebuilt -Dwolfssl-prefix is in use.
    build_step: ?*std.Build.Step = null,
};

// ---------------------------------------------------------------------------
// Host / target predicates
//
// Two independent questions matter for the C dependencies below, and mixing
// them up is what made this file Linux-only:
//
//   * what the *target* is      -> which wolfSSL/libwebsockets options are used
//                                  and whether the build is a cross build;
//   * what the *host* is        -> which tools exist. A Windows host has no
//                                  `sh`, no autotools and no `chmod`, so every
//                                  recipe has to be shell-free to work there.
// ---------------------------------------------------------------------------

fn targetIsWindows(target: std.Build.ResolvedTarget) bool {
    return target.result.os.tag == .windows;
}

fn hostIsWindows(b: *std.Build) bool {
    return b.graph.host.result.os.tag == .windows;
}

/// True when the requested target differs from the build host (in a way that
/// matters for the C dependency builds: OS or CPU architecture).
fn isCross(b: *std.Build, target: std.Build.ResolvedTarget) bool {
    const host = b.graph.host.result;
    return target.result.os.tag != host.os.tag or
        target.result.cpu.arch != host.cpu.arch;
}

/// The `-target` triple for `zig cc`, or null for a native build.
fn zigTargetTriple(b: *std.Build, target: std.Build.ResolvedTarget) ?[]const u8 {
    if (!isCross(b, target)) return null;
    return target.result.zigTriple(b.graph.arena) catch @panic("OOM");
}

/// Abort the build with a readable reason instead of a stack trace from a
/// missing tool halfway through a C build.
fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch fmt;
    @panic(std.fmt.allocPrint(std.heap.page_allocator, "\n{s}\n", .{msg}) catch msg);
}

/// Build parallelism for the C dependencies. `zig build -jN` is about Zig's own
/// steps; these are `cmake --build` runs that would otherwise serialise.
fn jobCount() []const u8 {
    const n = std.Thread.getCpuCount() catch 2;
    return std.fmt.allocPrint(std.heap.page_allocator, "{d}", .{n}) catch "2";
}

/// Locate `cmake`, or fail with an actionable message: both C dependencies are
/// built with CMake on every target except the POSIX autotools path, so it is
/// the one tool the build needs besides Zig itself.
fn cmakeProgram(b: *std.Build) []const u8 {
    return b.findProgram(&.{"cmake"}, &.{}) catch
        fatal(
        \\CMake was not found on PATH.
        \\
        \\The bundled wolfSSL/libwebsockets builds need CMake (they are the only
        \\portable way to configure those C libraries without a POSIX shell).
        \\Install it from https://cmake.org/download/ (on Windows, tick "Add CMake
        \\to the system PATH"), then re-run this command.
        , .{});
}

/// Pick a CMake generator that the host can actually run.
///
/// On a Unix host `cmake` defaults to "Unix Makefiles", which exists because
/// `make` does -- nothing to do. On Windows the default is the newest Visual
/// Studio generator, which needs MSVC even though the compiler is `zig cc`, so
/// a generator has to be chosen from the tools that are actually installed.
/// Override with -Dcmake-generator=NAME.
// `b.option` may only be declared once per build, but this helper is called
// once per C dependency, so the answer is memoised in build-script state (the
// build graph is constructed single-threaded, once).
var generator_override: ?[]const u8 = null;
var generator_override_read = false;

fn cmakeGenerator(b: *std.Build) []const u8 {
    if (!generator_override_read) {
        generator_override_read = true;
        generator_override = b.option(
            []const u8,
            "cmake-generator",
            "CMake generator for the bundled C dependencies (default: pick one the host can run)",
        );
    }
    if (generator_override) |g| {
        return g;
    }
    if (!hostIsWindows(b)) return "";
    for ([_][]const u8{ "ninja", "mingw32-make", "make" }) |tool| {
        if (b.findProgram(&.{tool}, &.{}) catch null) |_| {
            if (std.mem.eql(u8, tool, "ninja")) return "Ninja";
            return "MinGW Makefiles";
        }
    }
    fatal(
        \\No supported CMake generator on this Windows host.
        \\
        \\Building wolfSSL/libwebsockets needs a build tool: install Ninja
        \\(https://ninja-build.org/ -- one self-contained .exe on PATH), install
        \\MinGW-w64's mingw32-make, or pass -Dcmake-generator=... with one you
        \\already have. Visual Studio's generators work too if MSVC is installed.
        , .{});
}

// ---------------------------------------------------------------------------
// CMake driver
//
// A C dependency needs three CMake invocations in order (configure, build,
// install) plus a couple of post-install fixups. Chaining those is exactly what
// `sh -c "... && ..."` would be for -- and `sh` does not exist on a Windows
// host. `cmake -P <script>` is the portable substitute: it runs identically on
// every host, needs no shell, no executable bit and no per-OS quoting.
//
// The scripts are generated as files (they must exist on disk for `cmake -P`),
// are identical for every target, and take no paths as arguments: paths arrive
// through the environment, and the build step's output directory arrives as
// the script's argument (see `runCmakeScript`); `file(TO_CMAKE_PATH)` normalises
// Windows backslashes in both.
// ---------------------------------------------------------------------------

const CMAKE_SCRIPT_PREFIX =
    \\# Generated by yggdrasil.zig's build.zig -- do not edit.
    \\#
    \\# Configures, builds and installs one bundled C dependency without a shell,
    \\# so this works unchanged on a Windows host (no `sh`, no `cmd` quoting) and
    \\# on a Unix one. Inputs come from the environment and from the output
    \\# directory passed as the script's first argument.
    \\cmake_minimum_required(VERSION 3.20)
    \\
    \\# Zig passes each `addOutputDirectoryArg` to the process it runs, so the
    \\# output directory could not be baked into this generated file and cannot
    \\# be the working directory either (that would make the step depend on its
    \\# own output). It is always the last argument; its index depends on how
    \\# many -D switches precede -P, so it is computed from CMAKE_ARGC.
    \\math(EXPR LAST_ARG "${CMAKE_ARGC} - 1")
    \\set(OUT_DIR "${CMAKE_ARGV${LAST_ARG}}")
    \\if("${OUT_DIR}" STREQUAL "")
    \\  message(FATAL_ERROR "no output directory passed to ${CMAKE_ARGV2}")
    \\endif()
    \\file(TO_CMAKE_PATH "${OUT_DIR}" OUT_DIR)
    \\file(MAKE_DIRECTORY "${OUT_DIR}")
    \\
    \\file(TO_CMAKE_PATH "$ENV{YGG_DEP_SRC}" DEP_SRC)
    \\set(CFLAGS "$ENV{YGG_CFLAGS}")
    \\set(JOBS "$ENV{YGG_JOBS}")
    \\if(NOT JOBS)
    \\  set(JOBS 2)
    \\endif()
    \\if(NOT "${YGG_SHIM_DIR}" STREQUAL "")
    \\  file(TO_CMAKE_PATH "${YGG_SHIM_DIR}" SHIM_DIR_NATIVE)
    \\  set(CFLAGS "${CFLAGS} -I${SHIM_DIR_NATIVE}")
    \\endif()
    \\
    \\set(GENERATOR_ARGS "")
    \\if(NOT "$ENV{YGG_GENERATOR}" STREQUAL "")
    \\  list(APPEND GENERATOR_ARGS "-G$ENV{YGG_GENERATOR}")
    \\endif()
    \\set(CROSS_ARGS "")
    \\if(NOT "$ENV{YGG_SYSTEM_NAME}" STREQUAL "")
    \\  list(APPEND CROSS_ARGS
    \\       "-DCMAKE_SYSTEM_NAME=$ENV{YGG_SYSTEM_NAME}"
    \\       "-DCMAKE_SYSTEM_PROCESSOR=$ENV{YGG_SYSTEM_PROCESSOR}")
    \\endif()
    \\
;

const CMAKE_SCRIPT_SUFFIX =
    \\  WORKING_DIRECTORY "${OUT_DIR}"
    \\  COMMAND_ECHO STDOUT
    \\  RESULT_VARIABLE RC
    \\  ERROR_VARIABLE ERR)
    \\if(NOT RC EQUAL 0)
    \\  message(FATAL_ERROR "cmake configure failed (${RC}): ${ERR}")
    \\endif()
    \\
    \\execute_process(
    \\  COMMAND "${CMAKE_COMMAND}" --build "${OUT_DIR}/build" --config Release --parallel ${JOBS}
    \\  WORKING_DIRECTORY "${OUT_DIR}"
    \\  COMMAND_ECHO STDOUT
    \\  RESULT_VARIABLE RC
    \\  ERROR_VARIABLE ERR)
    \\if(NOT RC EQUAL 0)
    \\  message(FATAL_ERROR "cmake build failed (${RC}): ${ERR}")
    \\endif()
    \\
    \\execute_process(
    \\  COMMAND "${CMAKE_COMMAND}" --install "${OUT_DIR}/build" --config Release
    \\  WORKING_DIRECTORY "${OUT_DIR}"
    \\  COMMAND_ECHO STDOUT
    \\  RESULT_VARIABLE RC
    \\  ERROR_VARIABLE ERR)
    \\if(NOT RC EQUAL 0)
    \\  message(FATAL_ERROR "cmake install failed (${RC}): ${ERR}")
    \\endif()
    \\
;

/// `zquic`'s and libwebsockets' Windows ports include `<Psapi.h>` while the
/// MinGW headers ship `psapi.h`; a one-line shim include dir fixes the casing on
/// case-sensitive filesystems and on MinGW itself.
const PSAPI_SHIM = "#ifndef PSAPI_H_ALIAS\n#define PSAPI_H_ALIAS\n#include <psapi.h>\n#endif\n";

const CdepBuild = struct {
    out_dir: std.Build.LazyPath,
    step: *std.Build.Step,
};

/// Run `cmake -P <script>` for one bundled C dependency. `src` is the unpacked
/// package directory; everything is built inside the step's output directory.
fn runCmakeScript(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    src: std.Build.LazyPath,
    out_name: []const u8,
    script_name: []const u8,
    script: []const u8,
    /// Extra `-DCMAKE_C_FLAGS` material, typically warning downgrades. May be
    /// empty. Combined with the `-target` triple when cross-compiling.
    cflags: []const u8,
    /// Directory of casing shims to add with `-I` (passed as `-DYGG_SHIM_DIR=`),
    /// or null.
    shim_dir: ?std.Build.LazyPath,
    /// Another C dependency's step, so the two large C builds are serialised
    /// instead of being run concurrently (see `configureLibwebsockets`).
    after: ?*std.Build.Step,
) CdepBuild {
    const script_step = b.addWriteFiles();
    const script_file = script_step.add(script_name, script);

    const run = b.addSystemCommand(&.{cmakeProgram(b)});
    // The shim directory is a generated path, so it travels as an argv element
    // (resolved lazily by the step) rather than through `getPath`, which can
    // only be called on files that already exist.
    if (shim_dir) |dir| run.addPrefixedDirectoryArg("-DYGG_SHIM_DIR=", dir);
    run.addArgs(&.{"-P"});
    run.addFileArg(script_file);
    // Appended last: the script reads it as CMAKE_ARGV3.
    const out_dir = run.addOutputDirectoryArg(out_name);
    if (after) |step| run.step.dependOn(step);

    run.setEnvironmentVariable("YGG_ZIG_EXE", b.graph.zig_exe);
    run.setEnvironmentVariable("YGG_JOBS", jobCount());
    run.setEnvironmentVariable("YGG_GENERATOR", cmakeGenerator(b));
    run.setEnvironmentVariable("YGG_CFLAGS", zigCFlags(b, target, cflags));
    if (zigTargetTriple(b, target)) |triple| {
        // CMake's own cross-compile switches: without CMAKE_SYSTEM_NAME it would
        // try to link and run a test binary built for the target.
        run.setEnvironmentVariable("YGG_SYSTEM_NAME", cmakeSystemName(target));
        run.setEnvironmentVariable("YGG_SYSTEM_PROCESSOR", cmakeSystemProcessor(target));
        run.setEnvironmentVariable("YGG_TARGET", triple);
    } else {
        run.setEnvironmentVariable("YGG_SYSTEM_NAME", "");
        run.setEnvironmentVariable("YGG_SYSTEM_PROCESSOR", "");
        run.setEnvironmentVariable("YGG_TARGET", "");
    }
    // `src` cannot be an argv element (quoting), so it travels by environment.
    run.setEnvironmentVariable("YGG_DEP_SRC", src.getPath(b));

    return .{ .out_dir = out_dir, .step = &run.step };
}

/// `-DCMAKE_C_FLAGS` value: the `-target` triple when cross-compiling (which is
/// how `zig cc` is told what to build for -- CMake passes only one word as the
/// compiler, so the target cannot go there) plus any per-dependency flags.
fn zigCFlags(b: *std.Build, target: std.Build.ResolvedTarget, extra: []const u8) []const u8 {
    if (zigTargetTriple(b, target)) |triple| {
        if (extra.len == 0) return std.fmt.allocPrint(b.allocator, "-target {s}", .{triple}) catch @panic("OOM");
        return std.fmt.allocPrint(b.allocator, "-target {s} {s}", .{ triple, extra }) catch @panic("OOM");
    }
    return extra;
}

fn cmakeSystemName(target: std.Build.ResolvedTarget) []const u8 {
    return switch (target.result.os.tag) {
        .windows => "Windows",
        .macos, .ios, .tvos, .watchos, .visionos => "Darwin",
        .linux => "Linux",
        .freebsd => "FreeBSD",
        .netbsd => "NetBSD",
        .openbsd => "OpenBSD",
        else => @tagName(target.result.os.tag),
    };
}

fn cmakeSystemProcessor(target: std.Build.ResolvedTarget) []const u8 {
    return switch (target.result.cpu.arch) {
        .x86_64 => "x86_64",
        .x86 => "x86",
        .aarch64 => "arm64",
        .arm => "arm",
        .riscv64 => "riscv64",
        .powerpc64le => "ppc64le",
        else => @tagName(target.result.cpu.arch),
    };
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

    // Windows (native or cross): CMake + `zig cc`. One code path for both hosts,
    // and it needs nothing but Zig and CMake -- no MSVC, no MinGW, no autotools.
    if (targetIsWindows(target)) {
        return configureWolfsslCmake(b, target, wolfssl_dep.path("."));
    }

    // Everything else uses autotools, which is a shell script: it therefore
    // requires a shell, i.e. a Unix-like *host*. (Cross-compiling to a Unix
    // target from Windows is not supported by autotools anyway -- it needs a
    // target SDK and a target compiler, so point at a prebuilt wolfSSL.)
    if (hostIsWindows(b)) {
        fatal(
            \\Bundled wolfSSL cannot be built for {s} on a Windows host.
            \\
            \\The bundled build uses wolfSSL's autotools configure, which needs a
            \\POSIX shell. Either build on a Unix-like host (including
            \\cross-compiling to Windows, which uses CMake instead), or build
            \\wolfSSL yourself and pass -Dwolfssl=system -Dwolfssl-prefix=PATH.
            , .{@tagName(target.result.os.tag)});
    }
    if (isCross(b, target)) {
        fatal(
            \\Bundled wolfSSL cross-compiles to Windows via CMake/zig cc; for other
            \\cross targets (here: {s} from {s}) pass
            \\-Dwolfssl=system -Dwolfssl-prefix=/path/to/target/wolfssl.
            , .{ @tagName(target.result.os.tag), @tagName(b.graph.host.result.os.tag) });
    }

    switch (target.result.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos => {},
        else => fatal("bundled wolfSSL needs a Unix-like host with sh, make, autoconf and libtool; pass -Dwolfssl-prefix for target {s}", .{@tagName(target.result.os.tag)}),
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

/// wolfSSL via CMake + `zig cc`. Used for every Windows build (native on
/// Windows and cross from anywhere), and driven by a generated CMake script so
/// no shell is involved.
fn configureWolfsslCmake(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    wolfssl_src: std.Build.LazyPath,
) WolfsslPaths {
    const script = CMAKE_SCRIPT_PREFIX ++
        \\execute_process(
        \\  COMMAND "${CMAKE_COMMAND}" -S "${DEP_SRC}" -B "${OUT_DIR}/build"
        \\          "-DCMAKE_INSTALL_PREFIX=${OUT_DIR}/install"
        \\          "-DCMAKE_C_COMPILER=$ENV{YGG_ZIG_EXE}"
        \\          "-DCMAKE_C_COMPILER_ARG1=cc"
        \\          "-DCMAKE_C_FLAGS=${CFLAGS}"
        \\          -DCMAKE_BUILD_TYPE=Release
        \\          ${GENERATOR_ARGS}
        \\          ${CROSS_ARGS}
        \\          -DBUILD_SHARED_LIBS=OFF
        \\          -DWOLFSSL_TLS13=yes
        \\          -DWOLFSSL_QUIC=yes
        \\          -DWOLFSSL_OPENSSLEXTRA=yes
        \\          -DWOLFSSL_SNI=yes
        \\          -DWOLFSSL_OPENSSLALL=yes
        \\          -DWOLFSSL_ED25519=yes
        \\          -DWOLFSSL_CURVE25519=yes
        \\          -DWOLFSSL_CERTGEN=yes
        \\          -DWOLFSSL_KEYGEN=yes
        \\
    ++ CMAKE_SCRIPT_SUFFIX ++
        \\if(NOT EXISTS "${OUT_DIR}/install/lib/libwolfssl.a")
        \\  message(FATAL_ERROR "wolfSSL install produced no install/lib/libwolfssl.a")
        \\endif()
        \\
    ;

    const built = runCmakeScript(
        b,
        target,
        wolfssl_src,
        "wolfssl",
        "build-wolfssl.cmake",
        script,
        "-Wno-error=date-time",
        null,
        null,
    );
    return .{
        .include_dir = built.out_dir.path(b, "install/include"),
        .static_lib = built.out_dir.path(b, "install/lib/libwolfssl.a"),
        .build_step = built.step,
    };
}

/// libwebsockets' own flags.
///
/// `-D_GNU_SOURCE` is not decoration: lws's pty helper (`unix-spawn.c`) calls
/// `posix_openpt`/`grantpt`, which glibc only declares with a feature-test
/// macro set. A system gcc defines one by default; `zig cc` (clang) does not,
/// so without this the build dies on an implicit function declaration.
fn lwsCFlags(target: std.Build.ResolvedTarget) []const u8 {
    const common = "-include pthread.h -Wno-error -Wno-unused-label -Wno-error=date-time -Wno-macro-redefined -Wno-error=int-conversion -Wno-error=incompatible-pointer-types";
    if (targetIsWindows(target)) return common;
    return "-D_GNU_SOURCE " ++ common;
}

const LwsPaths = struct {
    include_dir: std.Build.LazyPath,
    static_lib: std.Build.LazyPath,
};

fn configureLibwebsockets(b: *std.Build, target: std.Build.ResolvedTarget, after: ?*std.Build.Step) LwsPaths {
    const lws_dep = b.dependency("libwebsockets", .{});
    return configureLibwebsocketsCmake(b, target, lws_dep.path("."), after);
}

/// libwebsockets for every target: CMake + `zig cc`, driven by a generated
/// CMake script.
///
/// `after`, when non-null, is another C dependency's build step. wolfSSL and
/// libwebsockets are both large C builds and Zig would otherwise run them
/// concurrently; on a small machine (2 GB RAM) that gets them both killed by
/// the OOM killer partway through, which looks like a mysterious build failure
/// with no compiler error in the log. Serialising them costs a little wall time
/// on big machines and makes the build actually finish on small ones.
///
/// lws's win32 port assumes a case-insensitive filesystem (`<Psapi.h>`) and
/// gcc-style warnings, hence the casing shim and the downgraded clang
/// diagnostics that `zig cc` enables.
fn configureLibwebsocketsCmake(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lws_src: std.Build.LazyPath,
    after: ?*std.Build.Step,
) LwsPaths {
    const shim_step = b.addWriteFiles();
    _ = shim_step.add("Psapi.h", PSAPI_SHIM);

    const script = CMAKE_SCRIPT_PREFIX ++
        \\execute_process(
        \\  COMMAND "${CMAKE_COMMAND}" -S "${DEP_SRC}" -B "${OUT_DIR}/build"
        \\          "-DCMAKE_INSTALL_PREFIX=${OUT_DIR}/install"
        \\          "-DCMAKE_C_COMPILER=$ENV{YGG_ZIG_EXE}"
        \\          "-DCMAKE_C_COMPILER_ARG1=cc"
        \\          "-DCMAKE_C_FLAGS=${CFLAGS}"
        \\          -DCMAKE_BUILD_TYPE=Release
        \\          ${GENERATOR_ARGS}
        \\          ${CROSS_ARGS}
        \\          -DDISABLE_WERROR=ON
        \\          -DLWS_HAVE_PTHREAD_H=1
        \\          -DLWS_WITH_SSL=OFF
        \\          -DLWS_WITH_SCHANNEL=OFF
        \\          -DLWS_WITH_SHARED=OFF
        \\          -DLWS_WITH_STATIC=ON
        \\          -DLWS_WITHOUT_TESTAPPS=ON
        \\          -DLWS_WITHOUT_TEST_SERVER=ON
        \\          -DLWS_WITHOUT_TEST_CLIENT=ON
        \\          -DLWS_WITHOUT_TEST_PING=ON
        \\          -DLWS_WITH_MINIMAL_EXAMPLES=OFF
        \\          -DLWS_WITH_HTTP2=OFF
        \\          -DLWS_IPV6=ON
        \\
    ++ CMAKE_SCRIPT_SUFFIX ++
        \\# lws installs into lib64/ on some platforms, and names its static
        \\# archive libwebsockets_static.a on Windows; normalise both so the link
        \\# step below has one path to use.
        \\if(EXISTS "${OUT_DIR}/install/lib/libwebsockets_static.a" AND
        \\   NOT EXISTS "${OUT_DIR}/install/lib/libwebsockets.a")
        \\  file(RENAME
        \\       "${OUT_DIR}/install/lib/libwebsockets_static.a"
        \\       "${OUT_DIR}/install/lib/libwebsockets.a")
        \\endif()
        \\if(EXISTS "${OUT_DIR}/install/lib64/libwebsockets.a" AND
        \\   NOT EXISTS "${OUT_DIR}/install/lib/libwebsockets.a")
        \\  file(MAKE_DIRECTORY "${OUT_DIR}/install/lib")
        \\  file(COPY "${OUT_DIR}/install/lib64/libwebsockets.a"
        \\       DESTINATION "${OUT_DIR}/install/lib")
        \\endif()
        \\if(NOT EXISTS "${OUT_DIR}/install/lib/libwebsockets.a")
        \\  message(FATAL_ERROR "libwebsockets install produced no install/lib/libwebsockets.a")
        \\endif()
        \\
    ;

    const built = runCmakeScript(
        b,
        target,
        lws_src,
        "libwebsockets",
        "build-libwebsockets.cmake",
        script,
        lwsCFlags(target),
        shim_step.getDirectory(),
        after,
    );
    return .{
        .include_dir = built.out_dir.path(b, "install/include"),
        .static_lib = built.out_dir.path(b, "install/lib/libwebsockets.a"),
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
            // Interface enumeration for multicast discovery (GetAdaptersAddresses).
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
