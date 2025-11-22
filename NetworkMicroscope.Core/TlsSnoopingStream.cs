using System.Net.Sockets;

namespace NetworkMicroscope.Core;

public class TlsSnoopingStream : Stream
{
    private readonly Stream _innerStream;
    private readonly MemoryStream _capturedReads = new();
    private readonly MemoryStream _capturedWrites = new();

    public TlsSnoopingStream(Stream innerStream)
    {
        _innerStream = innerStream;
    }

    public byte[] GetReadBytes() => _capturedReads.ToArray();
    public byte[] GetWrittenBytes() => _capturedWrites.ToArray();

    public override bool CanRead => _innerStream.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _innerStream.CanWrite;
    public override long Length => _innerStream.Length;
    public override long Position { get => _innerStream.Position; set => throw new NotSupportedException(); }

    public override void Flush() => _innerStream.Flush();

    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = _innerStream.Read(buffer, offset, count);
        if (read > 0)
        {
            _capturedReads.Write(buffer, offset, read);
        }
        return read;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        int read = await _innerStream.ReadAsync(buffer, offset, count, cancellationToken);
        if (read > 0)
        {
            _capturedReads.Write(buffer, offset, read);
        }
        return read;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        _capturedWrites.Write(buffer, offset, count);
        _innerStream.Write(buffer, offset, count);
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        _capturedWrites.Write(buffer, offset, count);
        await _innerStream.WriteAsync(buffer, offset, count, cancellationToken);
    }

    public override void SetLength(long value) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
}