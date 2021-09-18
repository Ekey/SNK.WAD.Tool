using System;
using System.IO;
using System.Collections.Generic;

namespace SNK.Unpacker
{
    class WadUnpack
    {
        static Int64 dwBaseOffset = 0;
        static List<WadEntry> m_EntryTable = new List<WadEntry>();

        public static void iDoIt(String m_Archive, String m_DstFolder)
        {
            using (FileStream TFileStream = File.OpenRead(m_Archive))
            {
                UInt32 dwMagic = TFileStream.ReadUInt32();
                if (dwMagic != 0x52414741)
                {
                    Utils.iSetError("[ERROR]: Invalid magic of WAD archive file");
                    return;
                }

                Int32 dwVersionA = TFileStream.ReadInt32(); // 1
                Int32 dwVersionB = TFileStream.ReadInt32(); // 2
                Int32 dwReserved = TFileStream.ReadInt32(); // 0

                if (dwVersionA != 1 || dwVersionB != 2)
                {
                    Utils.iSetError("[ERROR]: Invalid version of WAD archive file");
                    return;
                }

                UInt32 dwEntryTableSize = TFileStream.ReadUInt32();
                UInt32 dwIsEntryEncrypted = dwEntryTableSize & 0x80000000;

                m_EntryTable.Clear();
                if (dwIsEntryEncrypted == 0x80000000)
                {
                    dwEntryTableSize &= 0x7fffffff;
                    Byte[] lpEntryTable = new Byte[dwEntryTableSize];

                    lpEntryTable = TFileStream.ReadBytes((Int32)dwEntryTableSize);
                    lpEntryTable = SNK_Cast128.iDecryptData(lpEntryTable);

                    using (var TMemoryReader = new MemoryStream(lpEntryTable))
                    {
                        Int32 dwTotalFiles = TMemoryReader.ReadInt32();
                        for (Int32 i = 0; i < dwTotalFiles; i++)
                        {
                            String m_FileName = TMemoryReader.ReadStringLength();
                            Int32 dwSize = TMemoryReader.ReadInt32();
                            UInt32 dwFlag = TMemoryReader.ReadUInt32();
                            Int64 dwOffset = TMemoryReader.ReadInt64();

                            var Entry = new WadEntry
                            {
                                m_FileName = m_FileName,
                                dwSize = dwSize,
                                dwFlag = (WadEncFlags)dwFlag,
                                dwOffset = dwOffset,
                            };

                            m_EntryTable.Add(Entry);
                        }
                        TMemoryReader.Dispose();
                    }

                    UInt32 dwRootTableSize = TFileStream.ReadUInt32();
                    UInt32 dwIsRootEncrypted = dwRootTableSize & 0x80000000;

                    if (dwIsRootEncrypted == 0x80000000)
                    {
                        dwRootTableSize &= 0x7fffffff;

                        Byte[] lpRootTable = new Byte[dwRootTableSize];
                        lpRootTable = TFileStream.ReadBytes((Int32)dwRootTableSize);
                        dwBaseOffset = TFileStream.Position;

                        SNK_Blowfish.iSetupKey(SNK_Keys.BLOWFISH_ROOT_KEY_V2);
                        lpRootTable = SNK_Blowfish.iDecryptData(lpRootTable);
                    }

                    foreach (var m_Entry in m_EntryTable)
                    {
                        Console.WriteLine("{0} -> FLAG: {1}, SIZE: {2}, OFFSET: {3:X16}", m_Entry.m_FileName, m_Entry.dwFlag, m_Entry.dwSize, m_Entry.dwOffset + dwBaseOffset);

                        String m_FullPath = m_DstFolder + m_Entry.m_FileName.Replace("/", @"\");
                        Utils.iCreateDirectory(m_FullPath);

                        TFileStream.Seek((Int64)m_Entry.dwOffset + dwBaseOffset, SeekOrigin.Begin);

                        if (m_Entry.dwFlag == WadEncFlags.NONE)
                        {
                            Byte[] lpBuffer = new Byte[m_Entry.dwSize];
                            lpBuffer = TFileStream.ReadBytes(m_Entry.dwSize);

                            File.WriteAllBytes(m_FullPath, lpBuffer);
                        }

                        if (m_Entry.dwFlag == WadEncFlags.ENCRYPTED || m_Entry.dwFlag == WadEncFlags.ENCRYPTED_COMPRESSED)
                        {
                            Int32 dwEncryptedSize = WadUtils.iGetEncryptedSize(m_Entry.dwSize);

                            Byte[] lpScrBuffer = new Byte[dwEncryptedSize];
                            lpScrBuffer = TFileStream.ReadBytes(dwEncryptedSize);

                            var m_ResourceKey = WadUtils.iGetResourceKeyV2(m_Entry.m_FileName, (UInt32)m_Entry.dwSize);
                            SNK_Blowfish.iSetupKey(m_ResourceKey);
                            lpScrBuffer = SNK_Blowfish.iDecryptData(lpScrBuffer);

                            Array.Resize(ref lpScrBuffer, m_Entry.dwSize);

                            //Decompress
                            if (m_Entry.dwFlag == WadEncFlags.ENCRYPTED_COMPRESSED)
                            {
                                Int32 dwDecompressedSize = BitConverter.ToInt32(lpScrBuffer, lpScrBuffer.Length - 8);
                                Byte[] lpDstBuffer = new Byte[dwDecompressedSize];
                                lpDstBuffer = WadCompression.iDecompress(lpScrBuffer, lpDstBuffer, dwDecompressedSize);

                                File.WriteAllBytes(m_FullPath, lpDstBuffer);
                            }
                            else
                            {
                                File.WriteAllBytes(m_FullPath, lpScrBuffer);
                            }
                        }
                    }
                }
                else
                {
                    TFileStream.Position -= 4;
                    Int32 dwTotalFiles = TFileStream.ReadInt32();
                    for (Int32 i = 0; i < dwTotalFiles; i++)
                    {
                        String m_FileName = TFileStream.ReadStringLength();
                        Int32 dwSize = TFileStream.ReadInt32();
                        UInt32 dwFlag = TFileStream.ReadUInt32();
                        Int64 dwOffset = TFileStream.ReadInt64();

                        var Entry = new WadEntry
                        {
                            m_FileName = m_FileName,
                            dwSize = dwSize,
                            dwFlag = (WadEncFlags)dwFlag,
                            dwOffset = dwOffset,
                        };

                        m_EntryTable.Add(Entry);
                    }

                    UInt64 dwRootType = TFileStream.ReadUInt64();

                    if (dwRootType == 2)
                    {
                        //Skip mess data
                        TFileStream.Position += 17;
                    }

                    //Root table
                    Int32 dwStringsCount = TFileStream.ReadInt32();
                    for (Int32 i = 0; i < dwStringsCount; i++)
                    {
                        var m_File = TFileStream.ReadStringLength();
                        TFileStream.Position += 1;
                    }

                    dwBaseOffset = TFileStream.Position;
                    foreach (var m_Entry in m_EntryTable)
                    {
                        Console.WriteLine("{0} -> FLAG: {1}, SIZE: {2}, OFFSET: {3:X16}", m_Entry.m_FileName, m_Entry.dwFlag, m_Entry.dwSize, m_Entry.dwOffset + dwBaseOffset);

                        String m_FullPath = m_DstFolder + m_Entry.m_FileName.Replace("/", @"\");
                        Utils.iCreateDirectory(m_FullPath);

                        Byte[] lpBuffer = new Byte[m_Entry.dwSize];
                        lpBuffer = TFileStream.ReadBytes(m_Entry.dwSize);

                        File.WriteAllBytes(m_FullPath, lpBuffer);
                    }
                }
                TFileStream.Dispose();
            }
        }
    }
}