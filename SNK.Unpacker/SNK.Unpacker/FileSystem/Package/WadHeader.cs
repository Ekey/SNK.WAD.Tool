using System;

namespace SNK.Unpacker
{
    class WadHeader
    {
        public UInt32 dwMagic { get; set; } //always > 0x52414741 (AGAR)
        public UInt32 dwVersionA { get; set; } //always > 1
        public UInt32 dwVersionB { get; set; } //always > 2, revious is 1
        public UInt64 dwReserved { get; set; } //always > 0
        public UInt32 dwTableSize { get; set; } // + 0x80000000 (if encrypted) > & 0x7fffffff
    }
}
