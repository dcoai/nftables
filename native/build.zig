const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create main port executable (JSON-only, uses libnftables)
    const port_exe = b.addExecutable(.{
        .name = "port_nftables",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/port.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Port only needs libnftables and cap (no Erlang ei, no libnftnl/mnl)
    port_exe.root_module.linkSystemLibrary("nftables", .{});
    port_exe.root_module.linkSystemLibrary("cap", .{});
    port_exe.linkLibC();

    b.installArtifact(port_exe);
}
