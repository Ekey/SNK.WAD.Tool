using System;
using System.Runtime.InteropServices;

namespace SNK.Unpacker
{
    class WadCompression
    {
        [DllImport("SNK.LZ4.dll", EntryPoint = "SNK_Decompress", CallingConvention = CallingConvention.StdCall)]
        public static extern void SNK_Decompress(Byte[] lpSrcBuffer, Byte[] lpDstBuffer, Int32 dwSize);

        public static Byte[] iDecompress(Byte[] lpSrcBuffer, Byte[] lpDstBuffer, Int32 dwSize)
        {
            SNK_Decompress(lpSrcBuffer, lpDstBuffer, dwSize);
            return lpDstBuffer;
        }
    }
}
