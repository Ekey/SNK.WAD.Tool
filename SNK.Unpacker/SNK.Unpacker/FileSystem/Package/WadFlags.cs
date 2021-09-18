using System;

namespace SNK.Unpacker
{
    [Flags]
    public enum WadEncFlags : uint
    {
        NONE = 0,
        ENCRYPTED = 0x80000000,
        ENCRYPTED_COMPRESSED = 0xc0000000
    }
}
