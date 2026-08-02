#nullable enable
namespace FxSsh.Logging
{
    /// <summary>
    /// No-op log sink. The default destination — the library is completely
    /// silent (and zero cost) until the host configures a real sink.
    /// </summary>
    public sealed class NullLogSink : ILogSink
    {
        public void Write(LogLevel level, string message, System.Exception? exception = null)
        {
            // Intentionally does nothing.
        }
    }
}
