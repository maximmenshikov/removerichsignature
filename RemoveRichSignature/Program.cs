using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Windows.Forms;

namespace RemoveRichSignature
{
    class Program
    {
        /// <summary>
        /// Removes Rich signature from executable file
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        static bool RemoveSignature(string path)
        {
            bool anythingChanged = false;
            try
            {
                var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite);
                int fileLength = (int)fs.Length;
                byte[] b = new byte[fileLength];
                fs.Read(b, 0, (int)fileLength);
                if (fileLength >= 0x200)
                {
                    for (int i = 0; i < 0x200; ++i)
                    {
                        if (BitConverter.ToUInt32(b, i) == 0x68636952) /* Rich */
                        {
                            uint xorMask = BitConverter.ToUInt32(b, i + 4);
                            int endIndex = i + 8;
                            int startIndex = -1;
                            
                            // let's find DanS signature to calculate Rich signature size.
                            for (int j = 0; j < endIndex; ++j)
                            {
                                if ((BitConverter.ToUInt32(b, j) ^ xorMask) == 0x536E6144)
                                {
                                    startIndex = j;
                                    break;
                                }
                            }
                            if (startIndex != -1)
                            {
                                byte[] emptyData = new byte[endIndex - startIndex];
                                emptyData.CopyTo(b, startIndex);
                                anythingChanged = true;
                            }
                        }
                    }
                }
                if (BitConverter.ToUInt16(b, 0) == 0x5A4D) /* MZ */
                {
                    // e_lfanew is a position of PE header.
                    uint e_lfanew = BitConverter.ToUInt16(b, 0x3C);

                    /* validating if it is really PE */
                    if (BitConverter.ToUInt16(b, (int)e_lfanew) == 0x4550)
                    {
                        if (b[e_lfanew + 0x5C] == 0x09) /* WinCE GUI */
                        {
                            if (b[e_lfanew + 0x1A] != 0x09 ||
                                b[e_lfanew + 0x40] != 0x07 ||
                                b[e_lfanew + 0x42] != 0x00 ||
                                b[e_lfanew + 0x48] != 0x07 ||
                                b[e_lfanew + 0x4A] != 0x00)
                            {
                                // linker version:
                                b[e_lfanew + 0x1A] = 0x09;

                                // subsystem:
                                b[e_lfanew + 0x40] = 0x07;
                                b[e_lfanew + 0x42] = 0x00;
                                b[e_lfanew + 0x48] = 0x07;
                                b[e_lfanew + 0x4A] = 0x00;
                                anythingChanged = true;
                            }
                        }
                    }
                }

                fs.Seek(0, SeekOrigin.Begin);
                fs.Write(b, 0, fileLength);

                fs.Close();
            }
            catch (Exception ex)
            {
                return false;
            }
            return anythingChanged;
        }

        /// <summary>
        /// Resigns Dynamics ROM-protected XAP
        /// </summary>
        /// <param name="path"></param>
        static void Sign(string path)
        {
            string args = "-file \"" + path + "\" " +
                            "-outfile \"" + path + "s\" " +
                            "-privkey \"" + Application.StartupPath + "\\privKeyPair.key" + "\"";
            Process.Start(Application.StartupPath + "\\bcrypt-pc.exe", args);
        }


        /// <summary>
        /// Removes Rich signatures from all executable files inside XAP
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        static bool RemoveSignaturesFromXap(string path)
        {
            /* cleaning up Temp folder */
            string tempFolder = Path.Combine(Path.GetTempPath(), "RemoveRS");
            if (!Directory.Exists(tempFolder))
                Directory.CreateDirectory(tempFolder);
            string xapExtractionPath = Path.Combine(tempFolder, path.GetHashCode().ToString());
            if (Directory.Exists(xapExtractionPath))
                Directory.Delete(xapExtractionPath, true);
            Directory.CreateDirectory(xapExtractionPath);

            /* actual removing */
            var zip = new Ionic.Zip.ZipFile(path);
            if (zip["/WMAppPRHeader.xml"] == null)
            {
                bool anythingChanged = false;
                bool resign = (zip["/AccountManager.dll"] != null) && (zip["/ComXapHandlerACM.dll"] != null);
                zip.ExtractAll(xapExtractionPath);
                var files = Directory.GetFiles(xapExtractionPath, "*.dll", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    if (file.ToLower().EndsWith(".dll"))
                    {
                        anythingChanged |= RemoveSignature(file);
                        if (resign)
                            Sign(file);
                    }

                }
                files = Directory.GetFiles(xapExtractionPath, "*.exe", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    if (file.ToLower().EndsWith(".exe"))
                    {
                        anythingChanged |= RemoveSignature(file);
                        if (resign)
                            Sign(file);
                    }
                }
                zip.Dispose();
                if (anythingChanged)
                {
                    zip = new Ionic.Zip.ZipFile();
                    zip.AddDirectory(xapExtractionPath);
                    zip.Save(path);
                }
                return true;
            }
            else
            {
                zip.Dispose();
                zip = null;
            }
            return false;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("RemoveRichSignature v1.0 by ultrashot");
            Console.WriteLine("Usage: RemoveRichSignature.exe -optionname <path>");
            Console.WriteLine("Removes Rich signature from executable files, changes Linker version to 9, changes subsystem to 7.0");
            Console.WriteLine("\t-file <file>: Removes signature from single file");
            Console.WriteLine("\t-processdir <dir> <extension>: Removes signatures from all files with specified extension from given folder");
            Console.WriteLine("\t-findxaps <dir>");
            Console.WriteLine("\t-findexes <dir>");
            Console.WriteLine("\t-finddlls <dir>");
            if (args.Length >= 1)
            {
                if (args[0] == "-file")
                {
                    if (args.Length > 1)
                    {
                        string file = args[1];
                        if (file.EndsWith(".xap"))
                        {
                            if (!RemoveSignaturesFromXap(file))
                                Console.WriteLine("Error occured while processing \"" + file + "\"");
                        }
                        else if (file.EndsWith(".dll") || file.EndsWith(".exe"))
                        {
                            if (!RemoveSignature(file))
                                Console.WriteLine("Error occured while processing \"" + file + "\"");
                        }
                    }
                }
                else if (args[0] == "-processdir")
                {
                    if (args.Length > 2)
                    {
                        string path = args[1];
                        string ext = args[2];
                        var files = Directory.GetFiles(path, ext, SearchOption.AllDirectories);
                        foreach (var file in files)
                        {
                            if (!RemoveSignature(file))
                                Console.WriteLine("Error occured while processing \"" + file + "\"");
                        }
                    }
                }
                else if (args[0] == "-findxaps")
                {
                    string path = AppDomain.CurrentDomain.BaseDirectory;
                    if (args.Length > 1)
                        path = args[1];
                    var files = Directory.GetFiles(path, "*.xap", SearchOption.AllDirectories);
                    foreach (var file in files)
                    {
                        if (!RemoveSignaturesFromXap(file))
                            Console.WriteLine("Error occured while processing \"" + file + "\"");
                    }
                }
                else if (args[0] == "-finddlls")
                {
                    string path = AppDomain.CurrentDomain.BaseDirectory;
                    if (args.Length > 1)
                        path = args[1];
                    var files = Directory.GetFiles(Path.Combine(path, "!rrs_exclusions"), "*.dllinc");
                    foreach (var file in files)
                    {
                        string f = Path.GetFileName(file).Replace(".dllinc", ".dll");
                        var files2 = Directory.GetFiles(path, f, SearchOption.AllDirectories);
                        foreach (var file2 in files2)
                        {
                            if (!RemoveSignature(file2))
                                Console.WriteLine("Error occured while processing \"" + file + "\"");
                        }
                    }
                }
                else if (args[0] == "-findexes")
                {
                    string path = AppDomain.CurrentDomain.BaseDirectory;
                    if (args.Length > 1)
                        path = args[1];
                    var files = Directory.GetFiles(path, "*.exe", SearchOption.AllDirectories);
                    foreach (var file in files)
                    {
                        string checkFile = Path.Combine(Path.Combine(path, "!rrs_exclusions"), Path.GetFileName(file).Replace(".exe", ".rrsexc"));
                        if (!File.Exists(checkFile))
                        {
                            if (!RemoveSignature(file))
                                Console.WriteLine("Error occured while processing \"" + file + "\"");
                        }
                        else
                        {
                            Console.WriteLine("\"" + file + "\" skipped");
                        }
                    }
                }
                else
                {
                    if (!RemoveSignature(args[0]))
                        Console.WriteLine("Error occured while processing \"" + args[0] + "\"");
                }
            }
        }
    }
}
