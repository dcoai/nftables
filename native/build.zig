const std = @import("std");

pub fn build(b: *std.Build) void {
    // Get Erlang root from environment (user must set ERL_ROOT)
    const erl_root = std.process.getEnvVarOwned(b.allocator, "ERL_ROOT") catch blk: {
        // Default to common asdf path - user can override with ERL_ROOT
        const home = std.process.getEnvVarOwned(b.allocator, "HOME") catch unreachable;
        break :blk b.fmt("{s}/.asdf/installs/erlang/28.1.1", .{home});
    };

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create executable with root module
    const exe = b.addExecutable(.{
        .name = "libnf_ex",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Add Erlang include and library paths
    const erl_include = b.fmt("{s}/usr/include", .{erl_root});
    const erl_lib = b.fmt("{s}/usr/lib", .{erl_root});

    exe.root_module.addIncludePath(.{ .cwd_relative = erl_include });
    exe.root_module.addLibraryPath(.{ .cwd_relative = erl_lib });

    // Link system libraries
    exe.root_module.linkSystemLibrary("nftnl", .{});
    exe.root_module.linkSystemLibrary("mnl", .{});
    exe.root_module.linkSystemLibrary("cap", .{});
    exe.root_module.linkSystemLibrary("ei", .{});
    exe.linkLibC();

    b.installArtifact(exe);

    // Create JSON port executable (uses libnftables instead of libnftnl)
    const json_exe = b.addExecutable(.{
        .name = "libnf_json",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/json_port.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // JSON port only needs libnftables and cap (no Erlang, no libnftnl/mnl)
    json_exe.root_module.linkSystemLibrary("nftables", .{});
    json_exe.root_module.linkSystemLibrary("cap", .{});
    json_exe.linkLibC();

    b.installArtifact(json_exe);

    // Create ETF port executable (uses ETF for communication + libnftables for nftables)
    const etf_exe = b.addExecutable(.{
        .name = "libnf_etf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/etf_port.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // ETF port needs libnftables, cap, and Erlang ei library
    etf_exe.root_module.addIncludePath(.{ .cwd_relative = erl_include });
    etf_exe.root_module.addLibraryPath(.{ .cwd_relative = erl_lib });
    etf_exe.root_module.linkSystemLibrary("nftables", .{});
    etf_exe.root_module.linkSystemLibrary("cap", .{});
    etf_exe.root_module.linkSystemLibrary("ei", .{});
    etf_exe.linkLibC();

    b.installArtifact(etf_exe);

    // Create Unified port executable (supports both JSON and ETF)
    const unified_exe = b.addExecutable(.{
        .name = "libnf_unified",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/unified_port.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Unified port needs libnftables, cap, and Erlang ei library (same as ETF port)
    unified_exe.root_module.addIncludePath(.{ .cwd_relative = erl_include });
    unified_exe.root_module.addLibraryPath(.{ .cwd_relative = erl_lib });
    unified_exe.root_module.linkSystemLibrary("nftables", .{});
    unified_exe.root_module.linkSystemLibrary("cap", .{});
    unified_exe.root_module.linkSystemLibrary("ei", .{});
    unified_exe.linkLibC();

    b.installArtifact(unified_exe);
}
