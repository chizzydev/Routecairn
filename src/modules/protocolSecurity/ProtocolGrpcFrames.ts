/** A successful gRPC status cannot authenticate malformed or truncated message
 * framing. Compressed message interpretation requires a separate negotiated
 * decoder; unsupported compression remains inconclusive. */
export function decodeGrpcFrames(body: Buffer, maxMessages: number): { frames: Buffer[]; errorCode?: string } {
  const frames: Buffer[] = []; let offset = 0;
  while (offset < body.length) {
    if (frames.length >= maxMessages) return { frames: [], errorCode: "GRPC_MESSAGE_LIMIT_EXCEEDED" };
    if (offset + 5 > body.length) return { frames: [], errorCode: "GRPC_FRAME_TRUNCATED" };
    if (body[offset] !== 0) return { frames: [], errorCode: body[offset] === 1 ? "GRPC_MESSAGE_COMPRESSION_UNSUPPORTED" : "GRPC_FRAME_FLAG_INVALID" };
    const length = body.readUInt32BE(offset + 1);
    if (offset + 5 + length > body.length) return { frames: [], errorCode: "GRPC_FRAME_TRUNCATED" };
    frames.push(body.subarray(offset + 5, offset + 5 + length)); offset += 5 + length;
  }
  return { frames };
}
