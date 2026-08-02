namespace FxSsh.Logging
{
    /// <summary>
    /// Log severity levels. Ordered so that <c>(int)level</c> comparisons work:
    /// <c>IsEnabled(level) == (int)level >= MinLevel</c>.
    /// </summary>
    public enum LogLevel
    {
        /// <summary>Protocol-level detail: per-packet receive/send, window adjustments.</summary>
        Trace = 0,

        /// <summary>Diagnostics and lifecycle: session lifecycle, keepalive probes, algorithm negotiation.</summary>
        Debug = 1,

        /// <summary>Important business events: connection established, auth success, service registration, port binding.</summary>
        Info = 2,

        /// <summary>Recoverable anomalies: auth failure, rejected requests, minor protocol violations.</summary>
        Warn = 3,

        /// <summary>Faults that need attention: MAC/tag verification failure, lost connection, session-fatal exceptions.</summary>
        Fail = 4,

        /// <summary>Server-level critical: listener startup failure, unrecoverable errors.</summary>
        Critical = 5,
    }
}
