const std = @import("std");

// C bindings for ei.h (Erlang Interface)
const c = @cImport({
    @cInclude("ei.h");
});

/// Represents a decoded request message from Elixir
pub const Request = struct {
    allocator: std.mem.Allocator,
    req_id: u64,
    command: []const u8,
    args: std.ArrayList(Term),

    pub fn deinit(self: *Request) void {
        self.allocator.free(self.command);
        for (self.args.items) |*term| {
            term.deinit(self.allocator);
        }
        self.args.deinit(self.allocator);
    }
};

/// Represents a term in the Erlang term format
pub const Term = union(enum) {
    atom: []const u8,
    integer: i64,
    unsigned: u64,
    binary: []const u8,
    tuple: std.ArrayList(Term),
    list: std.ArrayList(Term),

    pub fn deinit(self: *Term, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .atom => |s| allocator.free(s),
            .binary => |b| allocator.free(b),
            .tuple => |*list| {
                for (list.items) |*item| {
                    item.deinit(allocator);
                }
                list.deinit(allocator);
            },
            .list => |*list| {
                for (list.items) |*item| {
                    item.deinit(allocator);
                }
                list.deinit(allocator);
            },
            .integer => {},
            .unsigned => {},
        }
    }

    /// Helper to get an integer value
    pub fn asU64(self: Term) ?u64 {
        return switch (self) {
            .unsigned => |val| val,
            .integer => |val| if (val >= 0) @intCast(val) else null,
            else => null,
        };
    }

    /// Helper to get an atom string
    pub fn asAtom(self: Term) ?[]const u8 {
        return switch (self) {
            .atom => |s| s,
            else => null,
        };
    }

    /// Helper to get a binary/string
    pub fn asBinary(self: Term) ?[]const u8 {
        return switch (self) {
            .binary => |b| b,
            else => null,
        };
    }
};

/// Represents a response to send back to Elixir
pub const Response = struct {
    allocator: std.mem.Allocator,
    req_id: u64,
    payload: ResponsePayload,

    pub const ResponsePayload = union(enum) {
        ok: void,
        ok_value: u64,
        ok_string: []const u8,
        ok_u32: u32,
        ok_binary: []const u8,
        ok_list: [][]const u8,  // List of binaries
        error_msg: []const u8,
    };

    pub fn deinit(self: Response) void {
        switch (self.payload) {
            .error_msg => |msg| self.allocator.free(msg),
            .ok_string => |s| self.allocator.free(s),
            .ok_binary => |b| self.allocator.free(b),
            .ok_list => |list| {
                for (list) |item| {
                    self.allocator.free(item);
                }
                self.allocator.free(list);
            },
            else => {},
        }
    }
};

/// Read a message from stdin in packet mode (4-byte length prefix)
pub fn readMessage(allocator: std.mem.Allocator, file: std.fs.File) !Request {
    // Read 4-byte packet length (big-endian)
    var len_buf: [4]u8 = undefined;
    const bytes_read = try file.read(&len_buf);
    if (bytes_read == 0) {
        return error.EndOfStream;
    }
    if (bytes_read != 4) {
        return error.InvalidPacketHeader;
    }

    const packet_len = std.mem.readInt(u32, &len_buf, .big);
    if (packet_len == 0 or packet_len > 1024 * 1024) { // Max 1MB
        return error.PacketTooLarge;
    }

    // Read the packet data
    const packet_data = try allocator.alloc(u8, packet_len);
    defer allocator.free(packet_data);

    var total_read: usize = 0;
    while (total_read < packet_len) {
        const n = try file.read(packet_data[total_read..]);
        if (n == 0) {
            return error.IncompletePacket;
        }
        total_read += n;
    }

    // Decode ETF (makes copies of all data, so we can free packet_data)
    return try decodeRequest(allocator, packet_data);
}

/// Write a message to stdout in packet mode (4-byte length prefix)
pub fn writeMessage(file: std.fs.File, response: Response) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(response.allocator);

    // Encode the response as ETF
    try encodeResponse(&buf, response);

    // Write 4-byte length prefix (big-endian)
    const len: u32 = @intCast(buf.items.len);
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, len, .big);
    try file.writeAll(&len_buf);

    // Write the packet data
    try file.writeAll(buf.items);
}

/// Decode a request from ETF binary
fn decodeRequest(allocator: std.mem.Allocator, data: []const u8) !Request {
    var index: c_int = 0;
    var version: c_int = 0;

    // Check ETF version byte
    if (c.ei_decode_version(@ptrCast(data.ptr), &index, &version) != 0) {
        return error.InvalidETFVersion;
    }

    // Decode outer tuple: {req_id, command}
    var arity: c_int = 0;
    if (c.ei_decode_tuple_header(@ptrCast(data.ptr), &index, &arity) != 0 or arity != 2) {
        return error.InvalidRequestFormat;
    }

    // Decode req_id (first element)
    var req_id: c_ulong = 0;
    if (c.ei_decode_ulong(@ptrCast(data.ptr), &index, &req_id) != 0) {
        return error.InvalidRequestId;
    }

    // Decode command tuple: {command_atom, ...args}
    if (c.ei_decode_tuple_header(@ptrCast(data.ptr), &index, &arity) != 0 or arity < 1) {
        return error.InvalidCommandFormat;
    }

    // Decode command atom
    var atom_buf: [256]u8 = undefined;
    if (c.ei_decode_atom(@ptrCast(data.ptr), &index, &atom_buf) != 0) {
        return error.InvalidCommandAtom;
    }

    const atom_len = std.mem.indexOf(u8, &atom_buf, &[_]u8{0}) orelse atom_buf.len;
    const command = try allocator.dupe(u8, atom_buf[0..atom_len]);

    // Decode remaining elements as arguments
    var args: std.ArrayList(Term) = .empty;
    errdefer {
        for (args.items) |*arg| {
            arg.deinit(allocator);
        }
        args.deinit(allocator);
    }

    var i: usize = 1;
    while (i < arity) : (i += 1) {
        const term = try decodeTerm(allocator, data, &index);
        try args.append(allocator, term);
    }

    return Request{
        .allocator = allocator,
        .req_id = req_id,
        .command = command,
        .args = args,
    };
}

/// Decode a single term from ETF
fn decodeTerm(allocator: std.mem.Allocator, data: []const u8, index: *c_int) !Term {
    var term_type: c_int = 0;
    var term_size: c_int = 0;

    // Get the type of the next term
    if (c.ei_get_type(@ptrCast(data.ptr), index, &term_type, &term_size) != 0) {
        return error.InvalidTermType;
    }

    switch (term_type) {
        c.ERL_ATOM_EXT, c.ERL_SMALL_ATOM_EXT, c.ERL_ATOM_UTF8_EXT, c.ERL_SMALL_ATOM_UTF8_EXT => {
            var atom_buf: [256]u8 = undefined;
            if (c.ei_decode_atom(@ptrCast(data.ptr), index, &atom_buf) != 0) {
                return error.DecodeAtomFailed;
            }
            const atom_len = std.mem.indexOf(u8, &atom_buf, &[_]u8{0}) orelse atom_buf.len;
            const atom = try allocator.dupe(u8, atom_buf[0..atom_len]);
            return Term{ .atom = atom };
        },
        c.ERL_STRING_EXT, c.ERL_BINARY_EXT => {
            var binary_buf: [4096]u8 = undefined;
            var binary_len: c_long = 0;
            if (c.ei_decode_binary(@ptrCast(data.ptr), index, &binary_buf, &binary_len) != 0) {
                return error.DecodeBinaryFailed;
            }
            const binary = try allocator.dupe(u8, binary_buf[0..@intCast(binary_len)]);
            return Term{ .binary = binary };
        },
        c.ERL_SMALL_INTEGER_EXT, c.ERL_INTEGER_EXT => {
            var long_val: c_long = 0;
            if (c.ei_decode_long(@ptrCast(data.ptr), index, &long_val) != 0) {
                return error.DecodeIntegerFailed;
            }
            return Term{ .integer = long_val };
        },
        c.ERL_SMALL_BIG_EXT, c.ERL_LARGE_BIG_EXT => {
            var ulong_val: c_ulong = 0;
            if (c.ei_decode_ulong(@ptrCast(data.ptr), index, &ulong_val) != 0) {
                return error.DecodeUnsignedFailed;
            }
            return Term{ .unsigned = ulong_val };
        },
        else => {
            // For unsupported types, just skip them and return a placeholder
            _ = c.ei_skip_term(@ptrCast(data.ptr), index);
            return Term{ .atom = try allocator.dupe(u8, "unsupported_term") };
        },
    }
}

/// Encode a response as ETF binary
fn encodeResponse(buf: *std.ArrayList(u8), response: Response) !void {
    var ei_buf: [1024]u8 = undefined;
    var index: c_int = 0;

    // Encode version
    if (c.ei_encode_version(&ei_buf, &index) != 0) {
        return error.EncodeError;
    }

    // Encode tuple: {req_id, result}
    if (c.ei_encode_tuple_header(&ei_buf, &index, 2) != 0) {
        return error.EncodeError;
    }

    // Encode req_id
    if (c.ei_encode_ulong(&ei_buf, &index, response.req_id) != 0) {
        return error.EncodeError;
    }

    // Encode result based on payload type
    switch (response.payload) {
        .ok => {
            // Encode atom 'ok'
            if (c.ei_encode_atom(&ei_buf, &index, "ok") != 0) {
                return error.EncodeError;
            }
        },
        .ok_value => |value| {
            // Encode tuple {:ok, value}
            if (c.ei_encode_tuple_header(&ei_buf, &index, 2) != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_atom(&ei_buf, &index, "ok") != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_ulong(&ei_buf, &index, value) != 0) {
                return error.EncodeError;
            }
        },
        .ok_string => |str| {
            // Encode tuple {:ok, string}
            if (c.ei_encode_tuple_header(&ei_buf, &index, 2) != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_atom(&ei_buf, &index, "ok") != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_binary(&ei_buf, &index, @ptrCast(str.ptr), @intCast(str.len)) != 0) {
                return error.EncodeError;
            }
        },
        .ok_u32 => |value| {
            // Encode tuple {:ok, value}
            if (c.ei_encode_tuple_header(&ei_buf, &index, 2) != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_atom(&ei_buf, &index, "ok") != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_ulong(&ei_buf, &index, value) != 0) {
                return error.EncodeError;
            }
        },
        .ok_binary => |bin| {
            // Encode tuple {:ok, binary}
            if (c.ei_encode_tuple_header(&ei_buf, &index, 2) != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_atom(&ei_buf, &index, "ok") != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_binary(&ei_buf, &index, @ptrCast(bin.ptr), @intCast(bin.len)) != 0) {
                return error.EncodeError;
            }
        },
        .ok_list => |list| {
            // Encode tuple {:ok, [binary1, binary2, ...]}
            if (c.ei_encode_tuple_header(&ei_buf, &index, 2) != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_atom(&ei_buf, &index, "ok") != 0) {
                return error.EncodeError;
            }
            // Encode list header
            if (c.ei_encode_list_header(&ei_buf, &index, @intCast(list.len)) != 0) {
                return error.EncodeError;
            }
            // Encode each binary in the list
            for (list) |item| {
                if (c.ei_encode_binary(&ei_buf, &index, @ptrCast(item.ptr), @intCast(item.len)) != 0) {
                    return error.EncodeError;
                }
            }
            // Encode empty list to terminate
            if (c.ei_encode_empty_list(&ei_buf, &index) != 0) {
                return error.EncodeError;
            }
        },
        .error_msg => |msg| {
            // Encode tuple {:error, reason}
            if (c.ei_encode_tuple_header(&ei_buf, &index, 2) != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_atom(&ei_buf, &index, "error") != 0) {
                return error.EncodeError;
            }
            if (c.ei_encode_binary(&ei_buf, &index, @ptrCast(msg.ptr), @intCast(msg.len)) != 0) {
                return error.EncodeError;
            }
        },
    }

    // Copy encoded data to buffer
    try buf.appendSlice(response.allocator, ei_buf[0..@intCast(index)]);
}
