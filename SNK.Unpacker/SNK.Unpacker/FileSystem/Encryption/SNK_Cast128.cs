using System;

namespace SNK.Unpacker
{
    class SNK_Cast128
    {
        static UInt32 SHIFT(UInt32 dwValue, Int32 dwShift)
        {
            return (dwValue << dwShift) | (dwValue >> (32 - dwShift));
        }

        static UInt32 ADD(UInt32 R, UInt32 Km, UInt32 Kr)
        {
            UInt32 X = Km + R;
            UInt32 T = SHIFT(X, (Int32)Kr);

            return (SNK_Tables.CAST_S1[(T >> 8) & 0xff] ^ SNK_Tables.CAST_S2[T & 0xff]) + SNK_Tables.CAST_S4[(T >> 16) & 0xff] - SNK_Tables.CAST_S3[(T >> 24) & 0xff];
        }

        static UInt32 XOR(UInt32 R, UInt32 Km, UInt32 Kr)
        {
            UInt32 X = Km ^ R;
            UInt32 T = SHIFT(X, (Int32)Kr);

            return SNK_Tables.CAST_S1[(T >> 8) & 0xff] + SNK_Tables.CAST_S3[(T >> 24) & 0xff] - SNK_Tables.CAST_S2[T & 0xff] ^ SNK_Tables.CAST_S4[(T >> 16) & 0xff];
        }

        static UInt32 SUB(UInt32 R, UInt32 Km, UInt32 Kr)
        {
            UInt32 X = Km - R;
            UInt32 T = SHIFT(X, (Int32)Kr);

            return (SNK_Tables.CAST_S1[(T >> 8) & 0xff] + SNK_Tables.CAST_S2[T & 0xff] ^ SNK_Tables.CAST_S3[(T >> 24) & 0xff]) - SNK_Tables.CAST_S4[(T >> 16) & 0xff];
        }

        static void iEncryptBlock(Byte[] lpBuffer, Int32 dwOffset)
        {
            UInt32 R = BitConverter.ToUInt32(lpBuffer, dwOffset);
            UInt32 L = BitConverter.ToUInt32(lpBuffer, dwOffset + 4);

            R ^= ADD(L, SNK_Keys.CAST_KEY[0], SNK_Keys.CAST_KEY[1]);
            L ^= XOR(R, SNK_Keys.CAST_KEY[2], SNK_Keys.CAST_KEY[3]);
            R ^= SUB(L, SNK_Keys.CAST_KEY[4], SNK_Keys.CAST_KEY[5]);
            L ^= ADD(R, SNK_Keys.CAST_KEY[6], SNK_Keys.CAST_KEY[7]);
            R ^= XOR(L, SNK_Keys.CAST_KEY[8], SNK_Keys.CAST_KEY[9]);
            L ^= SUB(R, SNK_Keys.CAST_KEY[10], SNK_Keys.CAST_KEY[11]);
            R ^= ADD(L, SNK_Keys.CAST_KEY[12], SNK_Keys.CAST_KEY[13]);
            L ^= XOR(R, SNK_Keys.CAST_KEY[14], SNK_Keys.CAST_KEY[15]);
            R ^= SUB(L, SNK_Keys.CAST_KEY[16], SNK_Keys.CAST_KEY[17]);
            L ^= ADD(R, SNK_Keys.CAST_KEY[18], SNK_Keys.CAST_KEY[19]);
            R ^= XOR(L, SNK_Keys.CAST_KEY[20], SNK_Keys.CAST_KEY[21]);
            L ^= SUB(R, SNK_Keys.CAST_KEY[22], SNK_Keys.CAST_KEY[23]);
            R ^= ADD(L, SNK_Keys.CAST_KEY[24], SNK_Keys.CAST_KEY[25]);
            L ^= XOR(R, SNK_Keys.CAST_KEY[26], SNK_Keys.CAST_KEY[27]);
            R ^= SUB(L, SNK_Keys.CAST_KEY[28], SNK_Keys.CAST_KEY[29]);
            L ^= ADD(R, SNK_Keys.CAST_KEY[30], SNK_Keys.CAST_KEY[31]);

            lpBuffer[dwOffset + 0] = (Byte)L;
            lpBuffer[dwOffset + 1] = (Byte)(L >> 8);
            lpBuffer[dwOffset + 2] = (Byte)(L >> 16);
            lpBuffer[dwOffset + 3] = (Byte)(L >> 24);
            lpBuffer[dwOffset + 4] = (Byte)R;
            lpBuffer[dwOffset + 5] = (Byte)(R >> 8);
            lpBuffer[dwOffset + 6] = (Byte)(R >> 16);
            lpBuffer[dwOffset + 7] = (Byte)(R >> 24);
        }

        static void iDecryptBlock(Byte[] lpBuffer, Int32 dwOffset)
        {
            UInt32 L = BitConverter.ToUInt32(lpBuffer, dwOffset);
            UInt32 R = BitConverter.ToUInt32(lpBuffer, dwOffset + 4);

            L ^= ADD(R, SNK_Keys.CAST_KEY[30], SNK_Keys.CAST_KEY[31]);
            R ^= SUB(L, SNK_Keys.CAST_KEY[28], SNK_Keys.CAST_KEY[29]);
            L ^= XOR(R, SNK_Keys.CAST_KEY[26], SNK_Keys.CAST_KEY[27]);
            R ^= ADD(L, SNK_Keys.CAST_KEY[24], SNK_Keys.CAST_KEY[25]);
            L ^= SUB(R, SNK_Keys.CAST_KEY[22], SNK_Keys.CAST_KEY[23]);
            R ^= XOR(L, SNK_Keys.CAST_KEY[20], SNK_Keys.CAST_KEY[21]);
            L ^= ADD(R, SNK_Keys.CAST_KEY[18], SNK_Keys.CAST_KEY[19]);
            R ^= SUB(L, SNK_Keys.CAST_KEY[16], SNK_Keys.CAST_KEY[17]);
            L ^= XOR(R, SNK_Keys.CAST_KEY[14], SNK_Keys.CAST_KEY[15]);
            R ^= ADD(L, SNK_Keys.CAST_KEY[12], SNK_Keys.CAST_KEY[13]);
            L ^= SUB(R, SNK_Keys.CAST_KEY[10], SNK_Keys.CAST_KEY[11]);
            R ^= XOR(L, SNK_Keys.CAST_KEY[8], SNK_Keys.CAST_KEY[9]);
            L ^= ADD(R, SNK_Keys.CAST_KEY[6], SNK_Keys.CAST_KEY[7]);
            R ^= SUB(L, SNK_Keys.CAST_KEY[4], SNK_Keys.CAST_KEY[5]);
            L ^= XOR(R, SNK_Keys.CAST_KEY[2], SNK_Keys.CAST_KEY[3]);
            R ^= ADD(L, SNK_Keys.CAST_KEY[0], SNK_Keys.CAST_KEY[1]);

            lpBuffer[dwOffset + 0] = (Byte)R;
            lpBuffer[dwOffset + 1] = (Byte)(R >> 8);
            lpBuffer[dwOffset + 2] = (Byte)(R >> 16);
            lpBuffer[dwOffset + 3] = (Byte)(R >> 24);
            lpBuffer[dwOffset + 4] = (Byte)L;
            lpBuffer[dwOffset + 5] = (Byte)(L >> 8);
            lpBuffer[dwOffset + 6] = (Byte)(L >> 16);
            lpBuffer[dwOffset + 7] = (Byte)(L >> 24);
        }

        public static Byte[] iEncryptData(Byte[] lpBuffer)
        {
            Int32 dwOffset = 0;
            Int32 dwRounds = lpBuffer.Length >> 3;
            for (Int32 i = 0; i < dwRounds; i++, dwOffset += 8)
            {
                iEncryptBlock(lpBuffer, dwOffset);
            }

            return lpBuffer;
        }

        public static Byte[] iDecryptData(Byte[] lpBuffer)
        {
            Int32 dwOffset = 0;
            Int32 dwRounds = lpBuffer.Length >> 3;
            for (Int32 i = 0; i < dwRounds; i++, dwOffset += 8)
            {
                iDecryptBlock(lpBuffer, dwOffset);
            }

            return lpBuffer;
        }
    }
}
