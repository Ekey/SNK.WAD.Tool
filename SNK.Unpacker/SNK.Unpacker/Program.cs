using System;
using System.IO;
using System.Reflection;

namespace SNK.Unpacker
{
    class Program
    {
        static void Main(String[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("SNK HEROINES Tag Team Frenzy WAD Unpacker");
            Console.WriteLine("(c) 2021 Ekey (h4x0r) / v{0}\n", Assembly.GetExecutingAssembly().GetName().Version.ToString());
            Console.ResetColor();


            if (args.Length != 2)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("[Usage]");
                Console.WriteLine("    SNK.Unpacker <m_File> <m_Directory>");
                Console.WriteLine("    m_File - Source of WAD file");
                Console.WriteLine("    m_Directory - Destination directory\n");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[Examples]");
                Console.WriteLine("    SNK.Unpacker E:\\Games\\SNK\\assets.wad D:\\Unpacked\\assets");
                Console.ResetColor();
                return;
            }

            String m_Input = args[0];
            String m_Output = Utils.iCheckArgumentsPath(args[1]);

            if (!File.Exists("SNK.LZ4.dll"))
            {
                Utils.iSetError("[ERROR]: SNK.LZ4.dll module not found!");
                return;
            }

            if (!File.Exists(m_Input))
            {
                Utils.iSetError("[ERROR]: Input file -> " + m_Input + " <- does not exist!");
                return;
            }

            WadUnpack.iDoIt(m_Input, m_Output);
        }
    }
}
