using System;

namespace SNK.Unpacker
{
    class WadUtils
    {
        public static Int32 iGetEncryptedSize(Int32 dwSize)
        {
            Int32 dwBlockSize = 8;
            if ((dwSize & 7) != 0)
                dwBlockSize = 8 - (dwSize & 7);

            return dwSize + dwBlockSize;
        }

        public static Byte[] iGetResourceKeyV1(String m_FileName, UInt32 dwSize)
        {
            Byte[] m_ResourceKey = new Byte[16];
            Int64 dwKeyIndex = m_FileName[2] << 0x10 ^ dwSize & 0xff0000 |
                             m_FileName[3] << 0x18 ^ dwSize & 0xff000000 |
                             m_FileName[1] << 8 ^ dwSize & 0xff00 |
                             dwSize & 0xff ^ m_FileName[0];

            dwKeyIndex = ((dwKeyIndex >> 8 ^ dwKeyIndex) >> 8 ^ dwKeyIndex) & 0xff ^ dwKeyIndex >> 0x18;
            dwKeyIndex = dwKeyIndex >> 4 ^ dwKeyIndex;
            dwKeyIndex &= 0xF;

            Array.Copy(SNK_Keys.BLOWFISH_RESOURCE_KEYS_V1, dwKeyIndex, m_ResourceKey, 0, 16);

            return m_ResourceKey;
        }

        public static Byte[] iGetResourceKeyV2(String m_FileName, UInt32 dwSize)
        {
            Byte[] m_ResourceKey = new Byte[56];

            Int64 dwKeyIndex = m_FileName[2] << 0x10 ^ dwSize & 0xff0000 |
                             m_FileName[3] << 0x18 ^ dwSize & 0xff000000 |
                             m_FileName[1] << 8 ^ dwSize & 0xff00 |
                             dwSize & 0xff ^ m_FileName[0];

            dwKeyIndex = ((dwKeyIndex >> 8 ^ dwKeyIndex) >> 8 ^ dwKeyIndex) & 0xff ^ dwKeyIndex >> 0x18;
            dwKeyIndex = dwKeyIndex >> 4 ^ dwKeyIndex;
            dwKeyIndex &= 0xF;
            dwKeyIndex *= 56;

            Array.Copy(SNK_Keys.BLOWFISH_RESOURCE_KEYS_V2, dwKeyIndex, m_ResourceKey, 0, 56);

            return m_ResourceKey;
        }
    }
}
