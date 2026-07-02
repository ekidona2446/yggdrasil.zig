const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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
    exe.root_module.addIncludePath(.{ .cwd_relative = "/home/user/wolfssl" });
    exe.root_module.addLibraryPath(.{ .cwd_relative = "/home/user/wolfssl/src/.libs" });
    exe.root_module.linkSystemLibrary("wolfssl", .{});
    exe.root_module.linkSystemLibrary("m", .{});
    exe.root_module.linkSystemLibrary("pthread", .{});

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
    probe.root_module.addIncludePath(.{ .cwd_relative = "/home/user/wolfssl" });
    probe.root_module.addLibraryPath(.{ .cwd_relative = "/home/user/wolfssl/src/.libs" });
    probe.root_module.linkSystemLibrary("wolfssl", .{});
    probe.root_module.linkSystemLibrary("m", .{});
    probe.root_module.linkSystemLibrary("pthread", .{});

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
    const run_node_tests = b.addRunArtifact(node_tests);
    test_step.dependOn(&run_node_tests.step);
}
