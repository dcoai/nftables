const std = @import("std");
const libnftnl = @import("libnftnl.zig");

// Netlink message header structure (from linux/netlink.h)
pub const NlMsgHdr = extern struct {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
};

// Netlink error message structure (from linux/netlink.h)
pub const NlMsgErr = extern struct {
    err: c_int, // negative errno or 0 for ACK
    msg: NlMsgHdr, // original message header
};

/// Parse a netlink error from received buffer
/// Returns the error code (negative errno) or 0 for success
pub fn parseError(buf: []const u8) ?c_int {
    if (buf.len < @sizeOf(NlMsgHdr)) {
        return null;
    }

    const nlh: *const NlMsgHdr = @ptrCast(@alignCast(buf.ptr));

    // Check if this is an error message
    if (nlh.nlmsg_type != libnftnl.NLMSG_ERROR) {
        return null;
    }

    // Check if we have enough data for the error structure
    if (buf.len < @sizeOf(NlMsgHdr) + @sizeOf(c_int)) {
        return null;
    }

    // Skip past the outer netlink header to get to the error payload
    const payload = buf[@sizeOf(NlMsgHdr)..];
    const err: *const NlMsgErr = @ptrCast(@alignCast(payload.ptr));
    return err.err;
}

/// Map errno to human-readable error message
pub fn errnoToString(allocator: std.mem.Allocator, err: c_int) ![]const u8 {
    // err is typically negative for errors, positive for success
    const errno = if (err < 0) -err else err;

    return switch (errno) {
        0 => try allocator.dupe(u8, "Success"),
        1 => try allocator.dupe(u8, "Operation not permitted (EPERM)"),
        2 => try allocator.dupe(u8, "No such file or directory (ENOENT)"),
        3 => try allocator.dupe(u8, "No such process (ESRCH)"),
        4 => try allocator.dupe(u8, "Interrupted system call (EINTR)"),
        5 => try allocator.dupe(u8, "I/O error (EIO)"),
        6 => try allocator.dupe(u8, "No such device or address (ENXIO)"),
        9 => try allocator.dupe(u8, "Bad file descriptor (EBADF)"),
        11 => try allocator.dupe(u8, "Try again (EAGAIN)"),
        12 => try allocator.dupe(u8, "Out of memory (ENOMEM)"),
        13 => try allocator.dupe(u8, "Permission denied (EACCES)"),
        14 => try allocator.dupe(u8, "Bad address (EFAULT)"),
        16 => try allocator.dupe(u8, "Device or resource busy (EBUSY)"),
        17 => try allocator.dupe(u8, "File exists (EEXIST)"),
        19 => try allocator.dupe(u8, "No such device (ENODEV)"),
        22 => try allocator.dupe(u8, "Invalid argument (EINVAL)"),
        24 => try allocator.dupe(u8, "Too many open files (EMFILE)"),
        28 => try allocator.dupe(u8, "No space left on device (ENOSPC)"),
        32 => try allocator.dupe(u8, "Broken pipe (EPIPE)"),
        71 => try allocator.dupe(u8, "Protocol error (EPROTO)"),
        90 => try allocator.dupe(u8, "Message too long (EMSGSIZE)"),
        92 => try allocator.dupe(u8, "Protocol not available (ENOPROTOOPT)"),
        93 => try allocator.dupe(u8, "Protocol not supported (EPROTONOSUPPORT)"),
        95 => try allocator.dupe(u8, "Operation not supported (EOPNOTSUPP)"),
        97 => try allocator.dupe(u8, "Address family not supported (EAFNOSUPPORT)"),
        98 => try allocator.dupe(u8, "Address already in use (EADDRINUSE)"),
        99 => try allocator.dupe(u8, "Cannot assign requested address (EADDRNOTAVAIL)"),
        100 => try allocator.dupe(u8, "Network is down (ENETDOWN)"),
        101 => try allocator.dupe(u8, "Network is unreachable (ENETUNREACH)"),
        103 => try allocator.dupe(u8, "Software caused connection abort (ECONNABORTED)"),
        104 => try allocator.dupe(u8, "Connection reset by peer (ECONNRESET)"),
        105 => try allocator.dupe(u8, "No buffer space available (ENOBUFS)"),
        106 => try allocator.dupe(u8, "Transport endpoint is already connected (EISCONN)"),
        107 => try allocator.dupe(u8, "Transport endpoint is not connected (ENOTCONN)"),
        110 => try allocator.dupe(u8, "Connection timed out (ETIMEDOUT)"),
        111 => try allocator.dupe(u8, "Connection refused (ECONNREFUSED)"),
        else => try std.fmt.allocPrint(allocator, "Unknown error (errno={d})", .{errno}),
    };
}

/// Check if a netlink message is an error
pub fn isError(buf: []const u8) bool {
    if (buf.len < @sizeOf(NlMsgHdr)) {
        return false;
    }

    const nlh: *const NlMsgHdr = @ptrCast(@alignCast(buf.ptr));
    return nlh.nlmsg_type == libnftnl.NLMSG_ERROR;
}

/// Check if error is actually a success ACK
pub fn isSuccessAck(buf: []const u8) bool {
    if (parseError(buf)) |err| {
        return err == 0;
    }
    return false;
}
