//! Shared types and framing for the user-agent ↔ system-grabber IPC.
//!
//! Wire format: 4-byte big-endian length prefix, then a JSON object body.
//! Each message has a `type` field; payload fields depend on the type.

const std = @import("std");

/// Default socket path the grabber listens on. Override with --socket-path
/// for development runs without root.
pub const default_socket_path = "/var/run/skhd/grabber.sock";

/// Protocol version exchanged in `hello`. Bump when wire format changes
/// in a non-backwards-compatible way.
pub const protocol_version: u32 = 2;

/// Maximum size of a single framed message body (1 MiB). Guards against
/// runaway frames on a misbehaving peer.
pub const max_frame_bytes: usize = 1 * 1024 * 1024;

/// One device matcher. Both fields must match to apply the rule. If
/// omitted (null), the rule applies to all keyboards.
pub const Device = struct {
    vendor: u32,
    product: u32,
};

/// HID-level colon-form remap (`.remap X [device d] : Y`). Forwarded
/// to the grabber so it can rewrite the source usage before tap-hold
/// processing — `kIOHIDOptionsTypeSeizeDevice` bypasses the IOHIDLib
/// UserKeyMapping that hidutil sets, so colon-form rules can't reach
/// seized devices through hidutil alone.
pub const Remap = struct {
    src_usage: u32,
    dst_usage: u32,
    /// Device filter; required (the agent's parser rejects global
    /// remaps).
    device: Device,
};

/// A single tap-hold remap rule. Wire-stable: don't reorder/rename
/// without bumping protocol_version.
///
/// Hold action is one of:
/// - `hold_usage > 0`: emit that HID usage on hold (modifier-style),
/// - `hold_modifiers > 0`: hold several modifiers together (hyper),
/// - `hold_layer != null`: switch the agent into that mode while held.
///
/// Exactly one must be set; the forms are mutually exclusive. This
/// matches `.remap … { hold: <hid-key> | <mods> | <mode_name> }` in
/// the config.
pub const Rule = struct {
    /// HID usage of the source key on usage page 0x07 (e.g. 0x39 for
    /// caps_lock).
    src_usage: u32,
    /// HID usage emitted on tap.
    tap_usage: u32,
    /// HID usage emitted on hold. Zero when `hold_modifiers` or
    /// `hold_layer` is set.
    hold_usage: u32 = 0,
    /// Modifier usages held together, as a bitmask where bit i is
    /// usage 0xE0 + i. Zero when another hold form is used. Defaulted
    /// so an older agent that never sends the field still parses.
    hold_modifiers: u8 = 0,
    /// Mode name to push on hold; null when `hold_usage` is set.
    /// Owned by the wire payload's arena (parsed-from-JSON lifetime).
    hold_layer: ?[]const u8 = null,
    /// Optional device filter; null means "all keyboards".
    device: ?Device = null,
    /// Tap-hold timeout in milliseconds.
    timeout_ms: u32 = 200,
    /// QMK permissive_hold semantics.
    permissive_hold: bool = false,
    /// QMK hold_on_other_key_press semantics.
    hold_on_other_key_press: bool = false,
    /// QMK retro_tap semantics.
    retro_tap: bool = false,
};

/// Read one length-prefixed frame into `buf`. Returns the body length on
/// success. Errors if peer closed cleanly (EndOfStream) or sent a frame
/// larger than the caller-supplied buffer / `max_frame_bytes`.
pub fn readFrame(reader: *std.Io.Reader, buf: []u8) !usize {
    var len_bytes: [4]u8 = undefined;
    try reader.readSliceAll(&len_bytes);
    const len = std.mem.readInt(u32, &len_bytes, .big);
    if (len > max_frame_bytes) return error.FrameTooLarge;
    if (len > buf.len) return error.BufferTooSmall;
    try reader.readSliceAll(buf[0..len]);
    return @intCast(len);
}

/// Write one length-prefixed frame.
pub fn writeFrame(writer: *std.Io.Writer, body: []const u8) !void {
    if (body.len > max_frame_bytes) return error.FrameTooLarge;
    var len_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_bytes, @intCast(body.len), .big);
    try writer.writeAll(&len_bytes);
    try writer.writeAll(body);
}

/// Serialize an arbitrary value to JSON and send it as one framed
/// message. Caller passes an anonymous struct literal that includes a
/// `type` field — the value is serialized verbatim so callers control
/// the wire shape.
pub fn writeMessage(writer: *std.Io.Writer, allocator: std.mem.Allocator, value: anytype) !void {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    try std.json.Stringify.value(value, .{}, &aw.writer);
    try writeFrame(writer, aw.written());
}

test "frame round-trip" {
    var pipe_buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&pipe_buf);
    try writeFrame(&w, "hello world");

    var r = std.Io.Reader.fixed(w.buffered());
    var read_buf: [256]u8 = undefined;
    const n = try readFrame(&r, &read_buf);
    try std.testing.expectEqualStrings("hello world", read_buf[0..n]);
}

test "a modifier-set rule survives the wire round trip" {
    var pipe_buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&pipe_buf);

    // 0b1111 = lctrl, lshift, lalt, lcmd held together.
    try writeMessage(&w, std.testing.allocator, .{
        .@"type" = "apply_rules",
        .rules = [_]Rule{.{
            .src_usage = 0x39,
            .tap_usage = 0x6D,
            .hold_modifiers = 0b0000_1111,
            .device = .{ .vendor = 0x046D, .product = 0xC548 },
        }},
    });

    var r = std.Io.Reader.fixed(w.buffered());
    var read_buf: [512]u8 = undefined;
    const n = try readFrame(&r, &read_buf);

    const Body = struct { @"type": []const u8, rules: []Rule };
    var parsed = try std.json.parseFromSlice(Body, std.testing.allocator, read_buf[0..n], .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const rule = parsed.value.rules[0];
    try std.testing.expectEqual(@as(u8, 0b0000_1111), rule.hold_modifiers);
    // The single-usage field must stay clear, because the grabber picks
    // its hold branch by checking hold_modifiers before hold_usage.
    try std.testing.expectEqual(@as(u32, 0), rule.hold_usage);
    try std.testing.expectEqual(@as(?[]const u8, null), rule.hold_layer);
}

test "a rule from an older agent still parses without the field" {
    // `ignore_unknown_fields` protects new-agent → old-grabber, and the
    // default on hold_modifiers protects old-agent → new-grabber. Pin
    // the second direction so the default is never dropped.
    const json =
        \\{"src_usage":57,"tap_usage":41,"hold_usage":224,"timeout_ms":200}
    ;
    var parsed = try std.json.parseFromSlice(Rule, std.testing.allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 0xE0), parsed.value.hold_usage);
    try std.testing.expectEqual(@as(u8, 0), parsed.value.hold_modifiers);
}

test "writeMessage produces parseable JSON" {
    var pipe_buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&pipe_buf);

    try writeMessage(&w, std.testing.allocator, .{
        .@"type" = "hello",
        .uid = @as(u32, 501),
        .version = protocol_version,
    });

    var r = std.Io.Reader.fixed(w.buffered());
    var read_buf: [256]u8 = undefined;
    const n = try readFrame(&r, &read_buf);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, read_buf[0..n], .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("hello", obj.get("type").?.string);
    try std.testing.expectEqual(@as(i64, 501), obj.get("uid").?.integer);
}
