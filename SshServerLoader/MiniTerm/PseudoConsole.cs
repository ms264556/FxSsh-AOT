using System;
using Microsoft.Win32.SafeHandles;
using static MiniTerm.Native.PseudoConsoleApi;

namespace MiniTerm
{
    /// <summary>
    /// Utility functions around the new Pseudo Console APIs
    /// </summary>
    internal sealed class PseudoConsole : IDisposable
    {
        public static readonly IntPtr PseudoConsoleThreadAttribute = (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE;

        public IntPtr Handle { get; }

        private PseudoConsole(IntPtr handle)
        {
            this.Handle = handle;
        }

        internal static PseudoConsole Create(SafeFileHandle inputReadSide, SafeFileHandle outputWriteSide, int width, int height)
        {
            var createResult = CreatePseudoConsole(
                new COORD { X = (short)width, Y = (short)height },
                inputReadSide, outputWriteSide,
                0, out IntPtr hPC);
            if (createResult != 0)
            {
                throw new InvalidOperationException("Could not create psuedo console. Error Code " + createResult);
            }
            return new PseudoConsole(hPC);
        }

        /// <summary>
        /// Notifies the child pseudo console of a host console window size change,
        /// causing the child process (cmd.exe, powershell, etc.) to receive a
        /// WINDOW_BUFFER_SIZE_EVENT / SIGWINCH and re-lay out its output.
        /// </summary>
        internal void Resize(int width, int height)
        {
            var resizeResult = ResizePseudoConsole(this.Handle, new COORD { X = (short)width, Y = (short)height });
            if (resizeResult != 0)
            {
                throw new InvalidOperationException("Could not resize pseudo console. Error Code " + resizeResult);
            }
        }

        public void Dispose()
        {
            ClosePseudoConsole(Handle);
        }
    }
}
