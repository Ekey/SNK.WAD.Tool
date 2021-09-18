using System;

namespace SNK.Unpacker
{
    class WadEntry
    {
        public String m_FileName { get; set; }
        public Int32 dwSize { get; set; }
        public WadEncFlags dwFlag { get; set; }
        public Int64 dwOffset { get; set; }
    }
}