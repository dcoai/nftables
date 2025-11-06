const std = @import("std");

// C bindings for libnftables library
// Made public so other modules can access C types
pub const c = @cImport({
    @cInclude("nftables/libnftables.h");
});

// Opaque context type
pub const Context = *anyopaque;

// Message types for error handler
pub const MsgType = c.enum_nft_msg_type;

// Error handler callback type
pub const ErrorHandler = *const fn (
    priv: ?*anyopaque,
    msg_type: MsgType,
    code: c_uint,
    data: ?*const anyopaque,
    data2: ?*anyopaque,
) callconv(.C) void;

// Context creation flags
pub const NFT_CTX_DEFAULT: u32 = c.NFT_CTX_DEFAULT;

// Output flags (for nft_ctx_output_set_flags)
pub const NFT_CTX_OUTPUT_REVERSEDNS: u32 = (1 << 0);
pub const NFT_CTX_OUTPUT_SERVICE: u32 = (1 << 1);
pub const NFT_CTX_OUTPUT_STATELESS: u32 = (1 << 2);
pub const NFT_CTX_OUTPUT_HANDLE: u32 = (1 << 3);
pub const NFT_CTX_OUTPUT_JSON: u32 = (1 << 4);
pub const NFT_CTX_OUTPUT_ECHO: u32 = (1 << 5);
pub const NFT_CTX_OUTPUT_GUID: u32 = (1 << 6);
pub const NFT_CTX_OUTPUT_NUMERIC_PROTO: u32 = (1 << 7);
pub const NFT_CTX_OUTPUT_NUMERIC_PRIO: u32 = (1 << 8);
pub const NFT_CTX_OUTPUT_NUMERIC_SYMBOL: u32 = (1 << 9);
pub const NFT_CTX_OUTPUT_NUMERIC_TIME: u32 = (1 << 10);
pub const NFT_CTX_OUTPUT_NUMERIC_ALL: u32 = (NFT_CTX_OUTPUT_NUMERIC_PROTO |
    NFT_CTX_OUTPUT_NUMERIC_PRIO |
    NFT_CTX_OUTPUT_NUMERIC_SYMBOL |
    NFT_CTX_OUTPUT_NUMERIC_TIME);
pub const NFT_CTX_OUTPUT_TERSE: u32 = (1 << 11);

// Input flags
pub const NFT_CTX_INPUT_NO_DNS: u32 = (1 << 0);
pub const NFT_CTX_INPUT_JSON: u32 = (1 << 1);

/// Create a new nftables context
pub fn ctxNew(flags: u32) ?Context {
    const ctx = c.nft_ctx_new(flags);
    if (ctx == null) {
        return null;
    }
    return @ptrCast(ctx);
}

/// Free nftables context
pub fn ctxFree(ctx: Context) void {
    c.nft_ctx_free(@ptrCast(@alignCast(ctx)));
}

/// Enable output buffering (capture output instead of writing to stdout)
pub fn ctxBufferOutput(ctx: Context) c_int {
    return c.nft_ctx_buffer_output(@ptrCast(@alignCast(ctx)));
}

/// Get the buffered output
pub fn ctxGetOutputBuffer(ctx: Context) ?[*:0]const u8 {
    const buf = c.nft_ctx_get_output_buffer(@ptrCast(@alignCast(ctx)));
    if (buf == null) {
        return null;
    }
    return buf;
}

/// Disable output buffering
pub fn ctxUnbufferOutput(ctx: Context) c_int {
    return c.nft_ctx_unbuffer_output(@ptrCast(@alignCast(ctx)));
}

/// Enable error buffering (capture errors instead of writing to stderr)
pub fn ctxBufferError(ctx: Context) c_int {
    return c.nft_ctx_buffer_error(@ptrCast(@alignCast(ctx)));
}

/// Get the buffered error
pub fn ctxGetErrorBuffer(ctx: Context) ?[*:0]const u8 {
    const buf = c.nft_ctx_get_error_buffer(@ptrCast(@alignCast(ctx)));
    if (buf == null) {
        return null;
    }
    return buf;
}

/// Disable error buffering
pub fn ctxUnbufferError(ctx: Context) c_int {
    return c.nft_ctx_unbuffer_error(@ptrCast(@alignCast(ctx)));
}

/// Set output flags
pub fn ctxOutputSetFlags(ctx: Context, flags: c_uint) void {
    c.nft_ctx_output_set_flags(@ptrCast(@alignCast(ctx)), flags);
}

/// Get output flags
pub fn ctxOutputGetFlags(ctx: Context) c_uint {
    return c.nft_ctx_output_get_flags(@ptrCast(@alignCast(ctx)));
}

/// Set input flags
pub fn ctxInputSetFlags(ctx: Context, flags: c_uint) void {
    c.nft_ctx_input_set_flags(@ptrCast(@alignCast(ctx)), flags);
}

/// Get input flags
pub fn ctxInputGetFlags(ctx: Context) c_uint {
    return c.nft_ctx_input_get_flags(@ptrCast(@alignCast(ctx)));
}

/// Set custom error handler
pub fn ctxSetErrorHandler(
    ctx: Context,
    handler: ErrorHandler,
    priv: ?*anyopaque,
) void {
    c.nft_ctx_set_error_handler(
        @ptrCast(@alignCast(ctx)),
        @ptrCast(handler),
        priv,
    );
}

/// Run command from buffer (string)
/// Returns 0 on success, non-zero on error
pub fn runCmdFromBuffer(ctx: Context, cmd: [*:0]const u8) c_int {
    return c.nft_run_cmd_from_buffer(@ptrCast(@alignCast(ctx)), cmd);
}

/// Run command from filename
/// Returns 0 on success, non-zero on error
pub fn runCmdFromFilename(ctx: Context, filename: [*:0]const u8) c_int {
    return c.nft_run_cmd_from_filename(@ptrCast(@alignCast(ctx)), filename);
}
