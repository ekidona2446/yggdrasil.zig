const std = @import("std");

const WolfsslMode = enum {
    /// Build wolfSSL from the Zig package dependency with autotools and link the
    /// resulting static archive into the executable. This is the default for
    /// native Unix-like builds.
    bundled,
    /// Use an already-built wolfSSL prefix passed with -Dwolfssl-prefix=PATH.
    system,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const wolfssl_mode = b.option(WolfsslMode, "wolfssl", "wolfSSL source: bundled (default) or system") orelse .bundled;
    const wolfssl_prefix = b.option([]const u8, "wolfssl-prefix", "Path to a wolfSSL install prefix containing include/ and lib/libwolfssl.a");

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

    const wolfssl = configureWolfssl(b, target, wolfssl_mode, wolfssl_prefix);

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

    b.installArtifact(exe);

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
    linkWolfssl(probe.root_module, wolfssl);

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
            .optimize = optimize,
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
            .optimize = optimize,
        }),
    });
    const run_util_tests = b.addRunArtifact(util_tests);
    test_step.dependOn(&run_util_tests.step);

    const async_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/async/async.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    async_tests.root_module.addImport("xev", xev_mod);
    const run_async_tests = b.addRunArtifact(async_tests);
    test_step.dependOn(&run_async_tests.step);

    const node_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/node/node.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    node_tests.root_module.addImport("ironwood", ironwood);
    node_tests.root_module.addImport("xev", xev_mod);
    node_tests.root_module.addImport("async", async_mod);
    linkWolfssl(node_tests.root_module, wolfssl);
    const run_node_tests = b.addRunArtifact(node_tests);
    test_step.dependOn(&run_node_tests.step);
}

const WolfsslPaths = struct {
    include_dir: std.Build.LazyPath,
    static_lib: std.Build.LazyPath,
};

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

    if (!target.query.isNative()) {
        @panic("bundled wolfSSL uses autotools for the native host only; for cross builds pass -Dwolfssl=system -Dwolfssl-prefix=/path/to/target/wolfssl");
    }

    switch (target.result.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos => {},
        else => @panic("bundled wolfSSL requires a Unix-like build host with sh, make, autoconf and libtool; pass -Dwolfssl-prefix for this target"),
    }

    const wolfssl_dep = b.dependency("wolfssl", .{});
    const run = b.addSystemCommand(&.{
        "sh",
        "-c",
        \\
        \\set -eu
        \\src="$1"
        \\out="$2"
        \\rm -rf "$out"
        \\mkdir -p "$out"
        \\cp -R "$src" "$out/src"
        \\cd "$out/src"
        \\if [ ! -x ./configure ]; then
        \\  ./autogen.sh
        \\fi
        \\./configure \
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
    };
}

fn linkWolfssl(module: *std.Build.Module, wolfssl: WolfsslPaths) void {
    module.addIncludePath(wolfssl.include_dir);
    // Add the archive by path instead of `-lwolfssl`, so the result is linked
    // statically even on systems that also have a shared libwolfssl installed.
    module.addObjectFile(wolfssl.static_lib);
    module.linkSystemLibrary("m", .{});
    module.linkSystemLibrary("pthread", .{});
}
