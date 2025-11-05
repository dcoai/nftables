const std = @import("std");

// Error handling for libnftnl and netlink operations

pub const NftError = error{
    NotImplemented,
    AllocationFailed,
    InvalidResourceId,
    InvalidResourceType,
    InvalidAttribute,
    ProtocolError,
    NetlinkError,
    CapabilityError,
    InvalidCommand,
};

pub fn mapLibnftnlError(errno: c_int) NftError {
    // TODO: Map errno values to meaningful errors
    _ = errno;
    return NftError.AllocationFailed;
}

pub fn mapNetlinkError(nlmsg_type: u16) NftError {
    // TODO: Parse netlink error messages
    _ = nlmsg_type;
    return NftError.NetlinkError;
}
