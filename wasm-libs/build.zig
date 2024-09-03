const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{ .cpu_arch = .wasm32, .os_tag = .wasi } });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const cbc = b.dependency("cbc", .{
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "aes",
        .root_source_file = b.path("aes.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    lib.root_module.addImport("cbc", cbc.module("cbc"));
    lib.linkLibrary(cbc.artifact("cbc"));
    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "aes",
        .root_source_file = b.path("aes.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    exe.rdynamic = true;
    exe.wasi_exec_model = .reactor;
    exe.entry = .disabled;
    exe.root_module.addImport("cbc", cbc.module("cbc"));
    exe.linkLibrary(cbc.artifact("cbc"));
    b.installArtifact(exe);
}
