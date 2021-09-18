using System;

namespace SNK.Unpacker
{
    class SNK_Blowfish
    {
        static UInt32 A = 0;
        static UInt32 B = 0;

        static UInt32[] PBOX;
        static UInt32[] SBOX1;
        static UInt32[] SBOX2;
        static UInt32[] SBOX3;
        static UInt32[] SBOX4;

        static UInt32 SWAP(UInt32 dwValue)
        {
            return ((dwValue & 0x000000ff) << 24) +
                   ((dwValue & 0x0000ff00) << 8) +
                   ((dwValue & 0x00ff0000) >> 8) +
                   ((dwValue & 0xff000000) >> 24);
        }

        static UInt32 iMakeRound(UInt32 A, UInt32 B, UInt32 dwIndex)
        {
            UInt32 X1 = (SBOX1[(B >> 24) & 0xff] + SBOX2[(B >> 16) & 0xff]) ^ SBOX3[(B >> 8) & 0xff];
            UInt32 X2 = X1 + SBOX4[B & 0xff];
            UInt32 X3 = X2 ^ PBOX[dwIndex];
            return X3 ^ A;
        }

        static void iCryptTable()
        {
            A ^= PBOX[0];
            for (UInt32 i = 0; i < 16; i += 2)
            {
                B = iMakeRound(B, A, i + 1);
                A = iMakeRound(A, B, i + 2);
            }
            B = B ^ PBOX[17];

            UInt32 dwSwap = A;
            A = B;
            B = dwSwap;
        }

        //Setup encryption key
        public static void iSetupKey(Byte[] m_Key)
        {
            PBOX = SNK_Tables.BLOWFISH_P.Clone() as UInt32[];
            SBOX1 = SNK_Tables.BLOWFISH_S1.Clone() as UInt32[];
            SBOX2 = SNK_Tables.BLOWFISH_S2.Clone() as UInt32[];
            SBOX3 = SNK_Tables.BLOWFISH_S3.Clone() as UInt32[];
            SBOX4 = SNK_Tables.BLOWFISH_S4.Clone() as UInt32[];

            Int32 j = 0;
            for (Int32 i = 0; i < 18; i++, j += 4)
            {
                UInt32 dwKey = SWAP(BitConverter.ToUInt32(m_Key, j % m_Key.Length));
                PBOX[i] ^= dwKey;
            }

            A = 0;
            B = 0;
            for (Int32 i = 0; i < 18; i += 2)
            {
                iCryptTable();
                PBOX[i] = A;
                PBOX[i + 1] = B;
            }

            for (Int32 i = 0; i < 256; i += 2)
            {
                iCryptTable();
                SBOX1[i] = A;
                SBOX1[i + 1] = B;
            }
            for (Int32 i = 0; i < 256; i += 2)
            {
                iCryptTable();
                SBOX2[i] = A;
                SBOX2[i + 1] = B;
            }
            for (Int32 i = 0; i < 256; i += 2)
            {
                iCryptTable();
                SBOX3[i] = A;
                SBOX3[i + 1] = B;
            }
            for (Int32 i = 0; i < 256; i += 2)
            {
                iCryptTable();
                SBOX4[i] = A;
                SBOX4[i + 1] = B;
            }
        }

        //Decrypt data
        public static Byte[] iDecryptData(Byte[] lpBuffer)
        {
            Int32 dwOffset = 0;
            Int32 dwRounds = lpBuffer.Length >> 3;
            for (Int32 i = 0; i < dwRounds; i++, dwOffset += 8)
            {
                UInt32 L = BitConverter.ToUInt32(lpBuffer, dwOffset);
                UInt32 R = BitConverter.ToUInt32(lpBuffer, dwOffset + 4);

                L ^= PBOX[17];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[16];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[15];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[14];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[13];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[12];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[11];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[10];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[9];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[8];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[7];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[6];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[5];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[4];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[3];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[2];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[1];

                lpBuffer[dwOffset + 0] = (Byte)(R ^ PBOX[0]);
                lpBuffer[dwOffset + 1] = (Byte)((R ^ PBOX[0]) >> 8);
                lpBuffer[dwOffset + 2] = (Byte)((R ^ PBOX[0]) >> 16);
                lpBuffer[dwOffset + 3] = (Byte)((R ^ PBOX[0]) >> 24);
                lpBuffer[dwOffset + 4] = (Byte)L;
                lpBuffer[dwOffset + 5] = (Byte)(L >> 8);
                lpBuffer[dwOffset + 6] = (Byte)(L >> 16);
                lpBuffer[dwOffset + 7] = (Byte)(L >> 24);
            }

            return lpBuffer;
        }

        //Encrypt data
        public static Byte[] iEncryptData(Byte[] lpBuffer)
        {
            Int32 dwOffset = 0;
            Int32 dwRounds = lpBuffer.Length >> 3;
            for (Int32 i = 0; i < dwRounds; i++, dwOffset += 8)
            {
                UInt32 L = BitConverter.ToUInt32(lpBuffer, dwOffset);
                UInt32 R = BitConverter.ToUInt32(lpBuffer, dwOffset + 4);

                L ^= PBOX[0];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[1];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[2];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[3];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[4];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[5];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[6];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[7];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[8];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[9];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[10];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[11];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[12];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[13];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[14];
                R ^= (SBOX1[L >> 24] + SBOX2[L >> 16 & 0xff] ^ SBOX3[L >> 8 & 0xff]) + SBOX4[L & 0xff] ^ PBOX[15];
                L ^= (SBOX1[R >> 24] + SBOX2[R >> 16 & 0xff] ^ SBOX3[R >> 8 & 0xff]) + SBOX4[R & 0xff] ^ PBOX[16];

                lpBuffer[dwOffset + 0] = (Byte)(R ^ PBOX[17]);
                lpBuffer[dwOffset + 1] = (Byte)((R ^ PBOX[17]) >> 8);
                lpBuffer[dwOffset + 2] = (Byte)((R ^ PBOX[17]) >> 16);
                lpBuffer[dwOffset + 3] = (Byte)((R ^ PBOX[17]) >> 24);
                lpBuffer[dwOffset + 4] = (Byte)L;
                lpBuffer[dwOffset + 5] = (Byte)(L >> 8);
                lpBuffer[dwOffset + 6] = (Byte)(L >> 16);
                lpBuffer[dwOffset + 7] = (Byte)(L >> 24);
            }

            return lpBuffer;
        }
    }
}
