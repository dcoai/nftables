const std = @import("std");

// C bindings for ei.h (Erlang Interface)
const c = @cImport({
    @cInclude("ei.h");
});

/// Helper for encoding ETF maps
pub const MapEncoder = struct {
    buf: [*c]u8,
    index: *c_int,

    pub fn init(buf: [*c]u8, index: *c_int) MapEncoder {
        return MapEncoder{
            .buf = buf,
            .index = index,
        };
    }

    /// Start encoding a map with the given number of keys
    pub fn startMap(self: *MapEncoder, size: usize) !void {
        if (c.ei_encode_map_header(self.buf, self.index, @intCast(size)) != 0) {
            return error.EncodeError;
        }
    }

    /// Encode a string key
    pub fn putAtom(self: *MapEncoder, key: []const u8) !void {
        if (c.ei_encode_atom_len(self.buf, self.index, @ptrCast(key.ptr), @intCast(key.len)) != 0) {
            return error.EncodeError;
        }
    }

    /// Encode a binary value
    pub fn putBinary(self: *MapEncoder, value: []const u8) !void {
        if (c.ei_encode_binary(self.buf, self.index, @ptrCast(value.ptr), @intCast(value.len)) != 0) {
            return error.EncodeError;
        }
    }

    /// Encode a u32 integer value
    pub fn putU32(self: *MapEncoder, value: u32) !void {
        if (c.ei_encode_ulong(self.buf, self.index, value) != 0) {
            return error.EncodeError;
        }
    }

    /// Encode a u64 integer value
    pub fn putU64(self: *MapEncoder, value: u64) !void {
        if (c.ei_encode_ulonglong(self.buf, self.index, value) != 0) {
            return error.EncodeError;
        }
    }

    /// Encode a c_int value
    pub fn putInt(self: *MapEncoder, value: c_int) !void {
        if (c.ei_encode_long(self.buf, self.index, value) != 0) {
            return error.EncodeError;
        }
    }

    /// Encode a boolean value
    pub fn putBool(self: *MapEncoder, value: bool) !void {
        const atom = if (value) "true" else "false";
        if (c.ei_encode_atom(self.buf, self.index, atom) != 0) {
            return error.EncodeError;
        }
    }

    /// Encode a key-value pair with atom key and binary value
    pub fn putKeyBinary(self: *MapEncoder, key: []const u8, value: []const u8) !void {
        try self.putAtom(key);
        try self.putBinary(value);
    }

    /// Encode a key-value pair with atom key and u32 value
    pub fn putKeyU32(self: *MapEncoder, key: []const u8, value: u32) !void {
        try self.putAtom(key);
        try self.putU32(value);
    }

    /// Encode a key-value pair with atom key and u64 value
    pub fn putKeyU64(self: *MapEncoder, key: []const u8, value: u64) !void {
        try self.putAtom(key);
        try self.putU64(value);
    }

    /// Encode a key-value pair with atom key and int value
    pub fn putKeyInt(self: *MapEncoder, key: []const u8, value: c_int) !void {
        try self.putAtom(key);
        try self.putInt(value);
    }

    /// Encode a key-value pair with atom key and boolean value
    pub fn putKeyBool(self: *MapEncoder, key: []const u8, value: bool) !void {
        try self.putAtom(key);
        try self.putBool(value);
    }

    /// Encode an optional string (null if not present)
    pub fn putKeyOptionalBinary(self: *MapEncoder, key: []const u8, value: ?[]const u8) !void {
        try self.putAtom(key);
        if (value) |v| {
            try self.putBinary(v);
        } else {
            // Encode nil atom
            if (c.ei_encode_atom(self.buf, self.index, "nil") != 0) {
                return error.EncodeError;
            }
        }
    }
};

/// Helper for encoding ETF lists
pub const ListEncoder = struct {
    buf: [*c]u8,
    index: *c_int,

    pub fn init(buf: [*c]u8, index: *c_int) ListEncoder {
        return ListEncoder{
            .buf = buf,
            .index = index,
        };
    }

    /// Start encoding a list with the given number of elements
    pub fn startList(self: *ListEncoder, size: usize) !void {
        if (c.ei_encode_list_header(self.buf, self.index, @intCast(size)) != 0) {
            return error.EncodeError;
        }
    }

    /// End the list (encode empty list terminator)
    pub fn endList(self: *ListEncoder) !void {
        if (c.ei_encode_empty_list(self.buf, self.index) != 0) {
            return error.EncodeError;
        }
    }
};
