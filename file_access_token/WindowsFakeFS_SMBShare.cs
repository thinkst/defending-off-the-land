using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Net;

// Tool Tip 
using System.Drawing;
using System.Windows.Forms;

using System.Threading.Tasks;
using System.Diagnostics;


/*
.\CanaryFS.exe C:\vfstest $(Get-Content .\csharp\test_file.csv -Raw) example.canarytokens.com true SecretFilesHere
*/

namespace ProjectedFileSystemProvider
{
    public class Program
    {
        public static void Main(string[] args)
        {

            // Expecting parameters in the format: rootPath debugMode csvFileName
            if (args.Length != 5)
            {
                Console.WriteLine("Usage: CanaryFS.exe <rootPath> <fileCsv> <alertDomain> <debugMode> <sharename>");
                return;
            }

            string rootPath = args[0];
            bool enableDebug = bool.Parse(args[3]);
            string alertDomain = args[2];
            string csvStr = args[1];
             string shrName = "";

            if(args[4] == null)
            {
                shrName = "FakeFS";
            }
            else
            {
                shrName = args[4];
            }

            Guid _guid = Guid.NewGuid();


            Console.WriteLine("Virtual Folder: " + rootPath);
            Console.WriteLine("Debug Mode: " + enableDebug);
			
		

            try
            {
                // Check if the root directory exists, create it if it doesn't
                if (!Directory.Exists(rootPath) )
                {
                    Directory.CreateDirectory(rootPath);
                    Console.WriteLine("Created directory: " + rootPath);
                }

                // Check available disk space
                DriveInfo drive = new DriveInfo(Path.GetPathRoot(rootPath));
                Console.WriteLine("Available free space: " + drive.AvailableFreeSpace + " bytes");

                var provider = new ProjFSProvider(rootPath, csvStr, alertDomain, enableDebug);

                int result = ProjFSNative.PrjMarkDirectoryAsPlaceholder(rootPath, null, IntPtr.Zero, ref _guid);

                provider.StartVirtualizing();
			
                bool shresult = false;	
                Console.WriteLine("Creating Share {0}", shrName);				
                

                shresult = SmbManager.CreateShare(rootPath, shrName);
                shresult = SmbManager.SetEveryoneReadAccess(shrName);

                Console.WriteLine("Projected File System Provider started. Press any key to exit.");
                Console.ReadKey();
                SmbManager.StopFolderSharing(shrName);

                provider.StopVirtualizing();


            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                if (ex is System.ComponentModel.Win32Exception)
                {
                    Console.WriteLine("Win32 Error Code: " + ((System.ComponentModel.Win32Exception)ex).NativeErrorCode);
                }
            }
            
        }
    }

    class ProjFSProvider
    {
        private readonly string rootPath;
        private readonly Dictionary<string, List<FileEntry>> fileSystem = new Dictionary<string, List<FileEntry>>();
        private IntPtr instanceHandle;
        private readonly bool enableDebug;

        private readonly string alertDomain;

        private static string BytesToBase32(byte[] bytes) {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            string output = "";
            for (int bitIndex = 0; bitIndex < bytes.Length * 8; bitIndex += 5) {
                int dualbyte = bytes[bitIndex / 8] << 8;
                if (bitIndex / 8 + 1 < bytes.Length)
                    dualbyte |= bytes[bitIndex / 8 + 1];
                dualbyte = 0x1f & (dualbyte >> (16 - bitIndex % 8 - 5));
                output += alphabet[dualbyte];
            }
            
            return output;
        }

        private void AlertOnFileAccess(string filePath, string imgFileName)
        {
            Console.WriteLine("Alerting on: {0} from process {1}", filePath, imgFileName);
            string filename = filePath.Split('\\')[filePath.Split('\\').Length - 1];
            string imgname = imgFileName.Split('\\')[imgFileName.Split('\\').Length - 1];
            string fnb32 = BytesToBase32(Encoding.UTF8.GetBytes(filename));
            string inb32 = BytesToBase32(Encoding.UTF8.GetBytes(imgname));
            Random rnd = new Random();
            string uniqueval = "u" + rnd.Next(1000, 10000).ToString() + ".";

            try {
                // Resolve the DNS
                DebugWrite(string.Format("Resolving the following hostname: {0}", uniqueval + "f" + fnb32 + ".i" + inb32 + "." + alertDomain));
                //Dns.GetHostEntry(uniqueval + "f" + fnb32 + ".i" + inb32 + "." + alertDomain);
                Task.Run(() => Dns.GetHostEntry(uniqueval + "f" + fnb32 + ".i" + inb32 + "." + alertDomain));
            } catch (Exception ex) {
                Console.WriteLine("Error: " + ex.Message);
            }
			
	    DebugWrite(string.Format("SMB Alert on: {0}", filePath));		
	    SMBAccessDetails(filePath);
        
        }
		
		
	private void SMBAccessDetails(string filePath)
	{
		// Monitor file access
		//Add RootPath
		string alertfilePath = rootPath +"\\"+filePath;
		 DebugWrite(string.Format("Alerting on SMB Access for {0} ", alertfilePath));
		SmbManager.PrintFileAccess(alertfilePath);
        
	}
		

        public ProjFSProvider(string rootPath, string csvStr, string alertDomain, bool enableDebug)
        {
            this.rootPath = rootPath;
            this.enableDebug = enableDebug;
            this.alertDomain = alertDomain;
            LoadFileSystemFromCsvString(csvStr);
        }


       private void LoadFileSystemFromCsvString(string csvStr)
        {
            foreach (var line in csvStr.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None))
            {
                var parts = line.Split(',');
                if (parts.Length != 4) continue;

                string path = parts[0].TrimStart('\\');
                string name = Path.GetFileName(path);
                string parentPath = Path.GetDirectoryName(path);
                bool isDirectory = bool.Parse(parts[1]);
                long fileSize = long.Parse(parts[2]);
                
                // Parse Unix timestamp
                long unixTimestamp = long.Parse(parts[3]);
                DateTime lastWriteTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTimestamp);

                if (string.IsNullOrEmpty(parentPath))
                {
                    parentPath = "\\";
                }

                if (!fileSystem.ContainsKey(parentPath))
                {
                    fileSystem[parentPath] = new List<FileEntry>();
                }

                fileSystem[parentPath].Add(new FileEntry
                {
                    Name = name,
                    IsDirectory = isDirectory,
                    FileSize = fileSize,
                    LastWriteTime = lastWriteTime,
                    Opened = false,
                    LastAlert = 0
                });
            }
        }

        public void StartVirtualizing()
        {
            ProjFSNative.PrjCallbacks callbacks = new ProjFSNative.PrjCallbacks
            {
                StartDirectoryEnumerationCallback = StartDirectoryEnumeration,
                EndDirectoryEnumerationCallback = EndDirectoryEnumeration,
                GetDirectoryEnumerationCallback = GetDirectoryEnumeration,
                GetPlaceholderInfoCallback = GetPlaceholderInfo,
                NotificationCallback = NotificationCB,
                GetFileDataCallback = GetFileData
            };

            ProjFSNative.PrjStartVirutalizingOptions options = new ProjFSNative.PrjStartVirutalizingOptions
            {
                flags = ProjFSNative.PrjStartVirutalizingFlags.PrjFlagNone,
                PoolThreadCount = 1,
                ConcurrentThreadCount = 1,
                NotificationMappings = new ProjFSNative.PrjNotificationMapping(),
                NotificationMappingCount = 0
            };

            Console.WriteLine("Attempting to start virtualization...");
            int hr = ProjFSNative.PrjStartVirtualizing(rootPath, ref callbacks, IntPtr.Zero, IntPtr.Zero, ref instanceHandle);
            if (hr != 0)
            {
                Console.WriteLine("PrjStartVirtualizing failed. HRESULT: " + hr);
                throw new System.ComponentModel.Win32Exception(hr);
            }
            Console.WriteLine("Virtualization started successfully.");
        }

        public void StopVirtualizing()
        {
            if (instanceHandle != IntPtr.Zero)
            {
                Console.WriteLine("Stopping virtualization...");
                
                ProjFSNative.PrjStopVirtualizing(instanceHandle);
                instanceHandle = IntPtr.Zero;

                // This is ugly to remove any hydrated files/folders.
                DirectoryInfo di = new DirectoryInfo(rootPath);
                foreach (FileInfo file in di.GetFiles())
                {
                    file.Delete(); 
                }
                foreach (DirectoryInfo dir in di.GetDirectories())
                {
                    dir.Delete(true); 
                }
                
                Console.WriteLine("Virtualization stopped.");
            }
        }

        private long GetUnixTimeStamp()
        {
            long ticks = DateTime.UtcNow.Ticks - DateTime.Parse("01/01/1970 00:00:00").Ticks;
            ticks /= 10000000; //Convert windows ticks to seconds
            return ticks;
        }

        private int NotificationCB(ProjFSNative.PrjCallbackData callbackData, bool isDirectory, ProjFSNative.PrjNotification notification, string destinationFileName, ref ProjFSNative.PrjNotificationParameters operationParameters)
        {
            if (notification != ProjFSNative.PrjNotification.FileOpened || isDirectory)
                return 0;

            string parentPath = Path.GetDirectoryName(callbackData.FilePathName);
            if (string.IsNullOrEmpty(parentPath))
            {
                parentPath = "\\";
            }
            string fileName = Path.GetFileName(callbackData.FilePathName);

            List<FileEntry> entries;
            if (!fileSystem.TryGetValue(parentPath, out entries))
            {
                return 0; // FILE_NOT_FOUND
            }

            var entry = entries.Find(e => string.Equals(e.Name, fileName, StringComparison.OrdinalIgnoreCase));
            if (entry == null || entry.IsDirectory)
            {
                DebugWrite("File is a dir?!");
                return 0; // ERROR_FILE_NOT_FOUND
            }
            if (entry.Opened && (GetUnixTimeStamp() - entry.LastAlert) > 5)
            {
                entry.LastAlert = GetUnixTimeStamp();
                AlertOnFileAccess(callbackData.FilePathName.ToLower(), callbackData.TriggeringProcessImageFileName);
				
				
				
            }

            return 0;
        }

        private int StartDirectoryEnumeration(ProjFSNative.PrjCallbackData callbackData, ref Guid enumerationId)
        {
            DebugWrite(string.Format("StartDirectoryEnumeration: {0}", callbackData.FilePathName ?? "\\"));
            return 0;
        }

        private int EndDirectoryEnumeration(ProjFSNative.PrjCallbackData callbackData, ref Guid enumerationId)
        {
            DebugWrite("EndDirectoryEnumeration");
            if (enumerationIndices.ContainsKey(enumerationId)) {
                enumerationIndices.Remove(enumerationId);
            }
            return 0;
        }


       private Dictionary<Guid, int> enumerationIndices = new Dictionary<Guid, int>();

        private int GetDirectoryEnumeration(ProjFSNative.PrjCallbackData callbackData, ref Guid enumerationId, string searchExpression, IntPtr dirEntryBufferHandle)
        {
            string directoryPath = callbackData.FilePathName ?? "";
            bool single = false;
            DebugWrite(string.Format("GetDirectoryEnumeration: {0}, {1}, EnumerationId: {2}", directoryPath, searchExpression, enumerationId));

            // Handle root directory
            if (string.IsNullOrEmpty(directoryPath))
            {
                directoryPath = "\\";
            }

            List<FileEntry> entries;
            if (!fileSystem.TryGetValue(directoryPath, out entries))
            {
                DebugWrite(string.Format("Directory not found: {0}", directoryPath));
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            int currentIndex;
            if (!enumerationIndices.TryGetValue(enumerationId, out currentIndex))
            {
                currentIndex = 0;
                enumerationIndices[enumerationId] = currentIndex;
            }

            if (callbackData.Flags == ProjFSNative.PrjCallbackDataFlags.RestartScan) {
                currentIndex = 0;
                enumerationIndices[enumerationId] = 0;
            } else if (callbackData.Flags == ProjFSNative.PrjCallbackDataFlags.ReturnSingleEntry) {
                single = true;
            }
            
            entries.Sort(delegate(FileEntry a, FileEntry b) { return ProjFSNative.PrjFileNameCompare(a.Name, b.Name); });

            for (; currentIndex < entries.Count; currentIndex++)
            {
                if (currentIndex >= entries.Count)
                {
                    DebugWrite(string.Format("Enumeration complete for session: {0}", enumerationId));
                    return ProjFSNative.S_OK;
                }
                
                var entry = entries[currentIndex];
                DebugWrite(string.Format("Processing entry: {0}", entry.Name));
                
                if (!ProjFSNative.PrjFileNameMatch(entry.Name, searchExpression)) // Skip if any don't match
                {
                    enumerationIndices[enumerationId] = currentIndex + 1;
                    continue;
                }
                
                ProjFSNative.PrjFileBasicInfo fileInfo = new ProjFSNative.PrjFileBasicInfo
                {
                    IsDirectory = entry.IsDirectory,
                    FileSize = entry.FileSize,
                    CreationTime = entry.LastWriteTime.ToFileTime(),
                    LastAccessTime = entry.LastWriteTime.ToFileTime(),
                    LastWriteTime = entry.LastWriteTime.ToFileTime(),
                    ChangeTime = entry.LastWriteTime.ToFileTime(),
                    FileAttributes = entry.IsDirectory ? FileAttributes.Directory : FileAttributes.Normal
                };
    
                int result = ProjFSNative.PrjFillDirEntryBuffer(entry.Name, ref fileInfo, dirEntryBufferHandle);
                if (result != ProjFSNative.S_OK)
                {
                    DebugWrite(string.Format("PrjFillDirEntryBuffer failed for {0}. Result: {1}", entry.Name, result));
                    return ProjFSNative.S_OK;
                }
    
                enumerationIndices[enumerationId] = currentIndex + 1;
                if (single)
                    return ProjFSNative.S_OK;
            }

            return ProjFSNative.S_OK;
        }

        private int GetPlaceholderInfo(ProjFSNative.PrjCallbackData callbackData)
        {
        
            string filePath = callbackData.FilePathName ?? "";
            DebugWrite(string.Format("GetPlaceholderInfo: {0}", filePath));

            if (string.IsNullOrEmpty(filePath))
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            string parentPath = Path.GetDirectoryName(filePath);
            string fileName = Path.GetFileName(filePath);

            if (string.IsNullOrEmpty(parentPath))
            {
                parentPath = "\\";
            }

            List<FileEntry> entries;
            if (!fileSystem.TryGetValue(parentPath, out entries))
            {
                DebugWrite(string.Format("Parent directory not found: {0}", parentPath));
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            FileEntry entry = null;
            foreach (var e in entries)
            {
                if (string.Equals(e.Name, fileName, StringComparison.OrdinalIgnoreCase))
                {
                    entry = e;
                    break;
                }
            }

            if (entry == null)
            {
                DebugWrite(string.Format("File not found: {0}", filePath));
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }
                        
            entries.Sort(delegate(FileEntry a, FileEntry b) { return ProjFSNative.PrjFileNameCompare(a.Name, b.Name); });

            ProjFSNative.PrjPlaceholderInfo placeholderInfo = new ProjFSNative.PrjPlaceholderInfo
            {
                FileBasicInfo = new ProjFSNative.PrjFileBasicInfo
                {
                    IsDirectory = entry.IsDirectory,
                    FileSize = entry.FileSize,
                    CreationTime = entry.LastWriteTime.ToFileTime(),
                    LastAccessTime = entry.LastWriteTime.ToFileTime(),
                    LastWriteTime = entry.LastWriteTime.ToFileTime(),
                    ChangeTime = entry.LastWriteTime.ToFileTime(),
                    FileAttributes = entry.IsDirectory ? FileAttributes.Directory : FileAttributes.Normal
                }
            };

           

            int result = ProjFSNative.PrjWritePlaceholderInfo(
                callbackData.NamespaceVirtualizationContext,
                filePath,
                ref placeholderInfo,
                (uint)Marshal.SizeOf(placeholderInfo));

            if (result != ProjFSNative.S_OK)
            {
                DebugWrite(string.Format("PrjWritePlaceholderInfo failed for {0}. Result: {1}", filePath, result));
            }

            return result;
            
           
        }

        private int GetFileData(ProjFSNative.PrjCallbackData callbackData, ulong byteOffset, uint length)
        {
            DebugWrite(string.Format("GetFileData: {0}, {1}, {2}", callbackData.FilePathName, byteOffset, length));

            string parentPath = Path.GetDirectoryName(callbackData.FilePathName);
            if (string.IsNullOrEmpty(parentPath))
            {
                parentPath = "\\";
            }
            string fileName = Path.GetFileName(callbackData.FilePathName);

            AlertOnFileAccess(callbackData.FilePathName, callbackData.TriggeringProcessImageFileName);
			SmbManager.PrintFileAccess(fileName);
            
            List<FileEntry> entries;
            if (!fileSystem.TryGetValue(parentPath, out entries))
            {
                DebugWrite("File not found!");
                return 2; // ERROR_FILE_NOT_FOUND
            }

            var entry = entries.Find(e => string.Equals(e.Name, fileName, StringComparison.OrdinalIgnoreCase));
            if (entry == null || entry.IsDirectory)
            {
                DebugWrite("File is a dir?!");
                return 2; // ERROR_FILE_NOT_FOUND
            }
            
            entry.Opened = true;
            entry.LastAlert = GetUnixTimeStamp();
            
            byte[] bom = {0xEF, 0xBB, 0xBF}; // UTF-8 Byte order mark
            byte[] textBytes = Encoding.UTF8.GetBytes(string.Format("This is the content of {0}", fileName));
            byte[] fileContent = new byte[bom.Length + textBytes.Length];
            System.Buffer.BlockCopy(bom, 0, fileContent, 0, bom.Length);
            System.Buffer.BlockCopy(textBytes, 0, fileContent, bom.Length, textBytes.Length);            
            
            if (byteOffset >= (ulong)fileContent.Length)
            {
                return 0;
            }

            uint bytesToWrite = Math.Min(length, (uint)(fileContent.Length - (int)byteOffset));
            IntPtr buffer = ProjFSNative.PrjAllocateAlignedBuffer(instanceHandle, bytesToWrite);
            try
            {
                Marshal.Copy(fileContent, (int)byteOffset, buffer, (int)bytesToWrite);
                return ProjFSNative.PrjWriteFileData(instanceHandle, ref callbackData.DataStreamId, buffer, byteOffset, bytesToWrite);
            }
            finally
            {
                ProjFSNative.PrjFreeAlignedBuffer(buffer);
            }
        }

        private void DebugWrite(string message)
        {
            if (enableDebug)
            {
                Console.WriteLine("[DEBUG] " + message);
            }
        }

    }

    class FileEntry
    {
        public string Name { get; set; }
        public bool IsDirectory { get; set; }
        public long FileSize { get; set; }
        public DateTime LastWriteTime { get; set; }
        public bool Opened { get; set; } 
        public long LastAlert { get; set; } 
    }

    static class ProjFSNative
    {
        public const int S_OK = 0;
        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        public const int ERROR_FILE_NOT_FOUND = 2;
       
       
        [DllImport("ProjectedFSLib.dll")]
        public static extern IntPtr PrjAllocateAlignedBuffer(IntPtr namespaceVirtualizationContext, uint size);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern bool PrjDoesNameContainWildCards(string fileName);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjFileNameCompare(string fileName1, string fileName2);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern bool PrjFileNameMatch(string fileNameToCheck, string pattern);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjFillDirEntryBuffer(string fileName, ref PrjFileBasicInfo fileBasicInfo,
            IntPtr dirEntryBufferHandle);

        [DllImport("ProjectedFSLib.dll")]
        public static extern void PrjFreeAlignedBuffer(IntPtr buffer);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjMarkDirectoryAsPlaceholder(string rootPathName, string targetPathName,
            IntPtr versionInfo, ref Guid virtualizationInstanceID);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjStartVirtualizing(string virtualizationRootPath, ref PrjCallbacks callbacks,
            IntPtr instanceContext, IntPtr options, ref IntPtr namespaceVirtualizationContext);

        [DllImport("ProjectedFSLib.dll")]
        public static extern void PrjStopVirtualizing(IntPtr namespaceVirtualizationContext);

        [DllImport("ProjectedFSLib.dll")]
        public static extern int PrjDeleteFile(IntPtr namespaceVirtualizationContext, string destinationFileName, int updateFlags, ref int failureReason);

        [DllImport("ProjectedFSLib.dll")]
        public static extern int PrjWriteFileData(IntPtr namespaceVirtualizationContext, ref Guid dataStreamId,
            IntPtr buffer, ulong byteOffset, uint length);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjWritePlaceholderInfo(IntPtr namespaceVirtualizationContext,
            string destinationFileName, ref PrjPlaceholderInfo placeholderInfo, uint placeholderInfoSize);

        // Structs and enums as provided
        [StructLayout(LayoutKind.Sequential)]
        public struct PrjFileEntry 
        {
            public string Name;
            public PrjFileBasicInfo FileBasicInfo;

        }


        [StructLayout(LayoutKind.Sequential)]
        public struct PrjCallbacks
        {
            public PrjStartDirectoryEnumerationCb StartDirectoryEnumerationCallback;
            public PrjEndDirectoryEnumerationCb EndDirectoryEnumerationCallback;
            public PrjGetDirectoryEnumerationCb GetDirectoryEnumerationCallback;
            public PrjGetPlaceholderInfoCb GetPlaceholderInfoCallback;
            public PrjGetFileDataCb GetFileDataCallback;
            public PrjQueryFileNameCb QueryFileNameCallback;
            public PrjNotificationCb NotificationCallback;
            public PrjCancelCommandCb CancelCommandCallback;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PrjCallbackData
        {
            public uint Size;
            public PrjCallbackDataFlags Flags;
            public IntPtr NamespaceVirtualizationContext;
            public int CommandId;
            public Guid FileId;
            public Guid DataStreamId;
            public string FilePathName;
            public IntPtr VersionInfo;
            public uint TriggeringProcessId;
            public string TriggeringProcessImageFileName;
            public IntPtr InstanceContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjFileBasicInfo
        {
            public bool IsDirectory;
            public long FileSize;
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public long ChangeTime;
            public FileAttributes FileAttributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjNotificationParameters
        {
            public PrjNotifyTypes PostCreateNotificationMask;
            public PrjNotifyTypes FileRenamedNotificationMask;
            public bool FileDeletedOnHandleCloseIsFileModified;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjPlaceholderInfo
        {
            public PrjFileBasicInfo FileBasicInfo;
            public uint EaBufferSize;
            public uint OffsetToFirstEa;
            public uint SecurityBufferSize;
            public uint OffsetToSecurityDescriptor;
            public uint StreamsInfoBufferSize;
            public uint OffsetToFirstStreamInfo;
            public PrjPlaceholderVersionInfo VersionInfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public byte[] VariableData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjStartVirutalizingOptions
        {
            public PrjStartVirutalizingFlags flags;
            public uint PoolThreadCount;
            public uint ConcurrentThreadCount;
            public PrjNotificationMapping NotificationMappings;
            public uint NotificationMappingCount;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjNotificationMapping
        {
            public PrjNotifyTypes NotificationBitMask;
            public string NotifcationRoot;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjPlaceholderVersionInfo
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)PrjPlaceholderID.Length)] public byte[] ProviderID;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)PrjPlaceholderID.Length)] public byte[] ContentID;
        }

         [StructLayout(LayoutKind.Sequential)]
         public struct EnumerationState
         {
            public string SessionID;
            public bool IsComplete;
            public int CurrentIndex;
         }

        [Flags]
        public enum PrjCallbackDataFlags : uint
        {
            RestartScan = 1,
            ReturnSingleEntry = 2
        }

        public enum PrjNotification : uint
        {
            FileOpened = 0x2,
            NewFileCreated = 0x4,
            FileOverwritten = 0x8,
            PreDelete = 0x10,
            PreRename = 0x20,
            PreSetHardlink = 0x40,
            FileRename = 0x80,
            HardlinkCreated = 0x100,
            FileHandleClosedNoModification = 0x200,
            FileHandleClosedFileModified = 0x400,
            FileHandleClosedFileDeleted = 0x800,
            FilePreConvertToFull = 0x1000
        }

        public enum PrjNotifyTypes : uint
        {
            None,
            SuppressNotifications,
            FileOpened,
            NewFileCreated,
            FileOverwritten,
            PreDelete,
            PreRename,
            PreSetHardlink,
            FileRenamed,
            HardlinkCreated,
            FileHandleClosedNoModification,
            FileHandleClosedFileModified,
            FileHandleClosedFileDeleted,
            FilePreConvertToFull,
            UseExistingMask
        }

        public enum PrjPlaceholderID : uint
        {
            Length = 128
        }

        public enum PrjStartVirutalizingFlags : uint
        {
            PrjFlagNone,
            PrjFlagUseNegativePathCache

        }

        public delegate int PrjCancelCommandCb(IntPtr callbackData);

        public delegate int PrjEndDirectoryEnumerationCb(PrjCallbackData callbackData, ref Guid enumerationId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjGetDirectoryEnumerationCb(PrjCallbackData callbackData, ref Guid enumerationId,
            string searchExpression, IntPtr dirEntryBufferHandle);

        public delegate int PrjGetFileDataCb(PrjCallbackData callbackData, ulong byteOffset, uint length);

        public delegate int PrjGetPlaceholderInfoCb(PrjCallbackData callbackData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjNotificationCb(PrjCallbackData callbackData, bool isDirectory, PrjNotification notification,
            string destinationFileName, ref PrjNotificationParameters operationParameters);

        public delegate int PrjStartDirectoryEnumerationCb(PrjCallbackData callbackData, ref Guid enumerationId);

        public delegate int PrjQueryFileNameCb(IntPtr callbackData);
    }
}


public class SmbManager
{

    [DllImport("netapi32.dll")]
    private static extern int NetShareDel(string serverName, string netName, int reserved);
    

    public static void StopFolderSharing(string shareName)
    {
        try
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "net";
            startInfo.Arguments = "share " + shareName + " /delete";
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.CreateNoWindow = true;

            using (Process process = Process.Start(startInfo))
            {
                process.WaitForExit();
                if (process.ExitCode != 0)
                {
                    throw new Exception("Failed to stop sharing folder '" + shareName + "'");
                }
            }
            
        }
        catch (Exception ex)
        {
             Console.WriteLine("Win32 Error Code: " + ((System.ComponentModel.Win32Exception)ex).NativeErrorCode);
        }
    }

    #region Structures
    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_INFO_3
    {
        public uint fi3_id;
        public uint fi3_permissions;
        public uint fi3_num_locks;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string fi3_pathname;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string fi3_username;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SESSION_INFO_10
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string sesi10_cname;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string sesi10_username;
        public uint sesi10_time;
        public uint sesi10_idle_time;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SHARE_INFO_2
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string shi2_netname;
        public uint shi2_type;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string shi2_remark;
        public uint shi2_permissions;
        public uint shi2_max_uses;
        public uint shi2_current_uses;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string shi2_path;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string shi2_passwd;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SHARE_INFO_502
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string shi502_netname;
        public uint shi502_type;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string shi502_remark;
        public uint shi502_permissions;
        public uint shi502_max_uses;
        public uint shi502_current_uses;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string shi502_path;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string shi502_passwd;
        public uint shi502_reserved;
        public IntPtr shi502_security_descriptor;
    }
    #endregion

    #region Constants
    private const uint SHARE_TYPE_DISKTREE = 0;
    private const uint ACCESS_READ = 1;
    private const uint ACCESS_ALL = 2032127;
    #endregion

    #region API Imports
    [DllImport("Netapi32.dll")]
    private static extern int NetFileEnum(
        string servername,
        string basepath,
        string username,
        uint level,
        out IntPtr bufptr,
        int prefmaxlen,
        out uint entriesread,
        out uint totalentries,
        IntPtr resume_handle);

    [DllImport("Netapi32.dll")]
    private static extern int NetSessionEnum(
        string servername,
        string clientname,
        string username,
        int level,
        out IntPtr bufptr,
        int prefmaxlen,
        out uint entriesread,
        out uint totalentries,
        IntPtr resume_handle);

    [DllImport("Netapi32.dll")]
    private static extern int NetShareAdd(
        string servername,
        int level,
        IntPtr bufptr,
        out int parm_err);

    [DllImport("Netapi32.dll")]
    private static extern int NetShareSetInfo(
        string servername,
        string netname,
        int level,
        IntPtr bufptr,
        out int parm_err);

    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr Buffer);

    [DllImport("Advapi32.dll", SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string StringSecurityDescriptor,
        uint StringSDRevision,
        out IntPtr SecurityDescriptor,
        out uint SecurityDescriptorSize);
    #endregion

    #region Public Methods
    public static void PrintFileAccess(string fullFilePath)
    {
        IntPtr bufPtr = IntPtr.Zero;
        uint entriesRead = 0;
        uint totalEntries = 0;
        Dictionary<string, string> sessions = new Dictionary<string, string>();

        try
        {
            int result = NetSessionEnum(null, null, null, 10, out bufPtr, -1, 
                out entriesRead, out totalEntries, IntPtr.Zero);

            if (result == 0 && bufPtr != IntPtr.Zero)
            {
                int dataSize = Marshal.SizeOf(typeof(SESSION_INFO_10));
                IntPtr current = bufPtr;

                for (int i = 0; i < entriesRead; i++)
                {
                    SESSION_INFO_10 data = (SESSION_INFO_10)Marshal.PtrToStructure(
                        current, 
                        typeof(SESSION_INFO_10));
                    
                    if (!string.IsNullOrEmpty(data.sesi10_username))
                    {
                        sessions[data.sesi10_username] = data.sesi10_cname;
                    }
                    current = (IntPtr)((long)current + dataSize);
                }
            }
        }
        finally
        {
            if (bufPtr != IntPtr.Zero)
            {
                NetApiBufferFree(bufPtr);
            }
        }

        bufPtr = IntPtr.Zero;
        try
        {
            int result = NetFileEnum(null, null, null, 3, out bufPtr, -1, 
                out entriesRead, out totalEntries, IntPtr.Zero);

            if (result == 0 && bufPtr != IntPtr.Zero)
            {
                int dataSize = Marshal.SizeOf(typeof(FILE_INFO_3));
                IntPtr current = bufPtr;

                for (int i = 0; i < entriesRead; i++)
                {
                    FILE_INFO_3 data = (FILE_INFO_3)Marshal.PtrToStructure(
                        current, 
                        typeof(FILE_INFO_3));
                    
                    if (data.fi3_pathname != null && 
                        data.fi3_pathname.Equals(fullFilePath, 
                            StringComparison.OrdinalIgnoreCase))
                    {
                        string remoteComputer = string.Empty;
                        sessions.TryGetValue(data.fi3_username, out remoteComputer);

                        Console.WriteLine("-------------------");
                        Console.WriteLine("File Path: {0}", data.fi3_pathname);
                        Console.WriteLine("User: {0}", data.fi3_username);
                        Console.WriteLine("Remote IP: {0}", 
                            remoteComputer != null ? remoteComputer.TrimStart('\\') : "Unknown");
                        Console.WriteLine("-------------------");

                        NotificationSystem.NotificationManager notifier = new NotificationSystem.NotificationManager();

                        notifier.ShowNotification(
                            message: string.Format("Canary FS Alert {0}, Accessed by {1} from {2}", data.fi3_pathname,data.fi3_username,remoteComputer ),
                            title: "Canary FS Alert! ", 
                            type: NotificationSystem.NotificationType.Warning, 
                            duration: 3000);    
                        

                        EventLog.WriteEntry("Application", string.Format("Canary FS Alert {0}, Accessed by {1} from {2}", data.fi3_pathname, data.fi3_username, remoteComputer), EventLogEntryType.Information);
                        
                        // Dispose when done
                        notifier.Dispose();
                    }
                    current = (IntPtr)((long)current + dataSize);
                }
            }
        }
        finally
        {
            if (bufPtr != IntPtr.Zero)
            {
                NetApiBufferFree(bufPtr);
            }
        }

        
    }

    public static bool CreateShare(string folderPath, string shareName)
    {
        SHARE_INFO_2 shareInfo = new SHARE_INFO_2
        {
            shi2_netname = shareName,
            shi2_type = SHARE_TYPE_DISKTREE,
            shi2_remark = "Created by SmbManager",
            shi2_permissions = ACCESS_ALL,
            shi2_max_uses = uint.MaxValue,
            shi2_current_uses = 0,
            shi2_path = folderPath,
            shi2_passwd = null
        };

        int paramErrorIndex;
        int bufferSize = Marshal.SizeOf(typeof(SHARE_INFO_2));
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

        try
        {
            Marshal.StructureToPtr(shareInfo, buffer, false);
            int result = NetShareAdd(null, 2, buffer, out paramErrorIndex);
            return result == 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error creating share: " + ex.Message);
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static bool SetEveryoneReadAccess(string shareName)
    {
        string sddl = "D:(A;;0x1200a9;;;WD)";
        IntPtr securityDescriptor;
        uint securityDescriptorSize;

        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            sddl, 
            1,
            out securityDescriptor, 
            out securityDescriptorSize))
        {
            Console.WriteLine("Error converting security descriptor");
            return false;
        }

        SHARE_INFO_502 shareInfo = new SHARE_INFO_502
        {
            shi502_netname = shareName,
            shi502_type = SHARE_TYPE_DISKTREE,
            shi502_remark = "Modified by SmbManager",
            shi502_permissions = ACCESS_READ,
            shi502_max_uses = uint.MaxValue,
            shi502_current_uses = 0,
            shi502_security_descriptor = securityDescriptor
        };

        int paramErrorIndex;
        int bufferSize = Marshal.SizeOf(typeof(SHARE_INFO_502));
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

        try
        {
            Marshal.StructureToPtr(shareInfo, buffer, false);
            int result = NetShareSetInfo(null, shareName, 502, buffer, out paramErrorIndex);
            return result == 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error setting share permissions: " + ex.Message);
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
            Marshal.FreeHGlobal(securityDescriptor);
        }
    }
    #endregion
}

namespace NotificationSystem
    {
        public class NotificationManager
        {
            private NotifyIcon notifyIcon;

            public NotificationManager()
            {
                InitializeNotifyIcon();
            }

            private void InitializeNotifyIcon()
            {
                notifyIcon = new NotifyIcon();
                notifyIcon.Icon = SystemIcons.Information;
                notifyIcon.Visible = true;
            }

            public void ShowNotification(string message)
            {
                ShowNotification(message, "Notification", NotificationType.Info, 5000);
            }

            public void ShowNotification(string message, string title, NotificationType type, int duration)
            {
                SetNotificationIcon(type);
                notifyIcon.BalloonTipTitle = title;
                notifyIcon.BalloonTipText = message;
                notifyIcon.BalloonTipIcon = ConvertToToolTipIcon(type);
                notifyIcon.ShowBalloonTip(duration);
            }

            private void SetNotificationIcon(NotificationType type)
            {
                switch (type)
                {
                    case NotificationType.Info:
                        notifyIcon.Icon = SystemIcons.Information;
                        break;
                    case NotificationType.Warning:
                        notifyIcon.Icon = SystemIcons.Warning;
                        break;
                    case NotificationType.Error:
                        notifyIcon.Icon = SystemIcons.Error;
                        break;
                    default:
                        notifyIcon.Icon = SystemIcons.Information;
                        break;
                }
            }

            private ToolTipIcon ConvertToToolTipIcon(NotificationType type)
            {
                switch (type)
                {
                    case NotificationType.Info:
                        return ToolTipIcon.Info;
                    case NotificationType.Warning:
                        return ToolTipIcon.Warning;
                    case NotificationType.Error:
                        return ToolTipIcon.Error;
                    default:
                        return ToolTipIcon.Info;
                }
            }

            public void Dispose()
            {
                if (notifyIcon != null)
                {
                    notifyIcon.Dispose();
                }
            }
        }

        public enum NotificationType
        {
            Info,
            Warning,
            Error
        }
    }
