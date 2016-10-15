using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.Management;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using CSUACSelfElevation;
using ProcessPrivileges;
using System.IO;


namespace WindowsFormsApplication1
{
    public partial class Form1 : Form
    {
        public static int MyGlobal=0;
        public Form1()
        {
            InitializeComponent();
        }
       
        private void Form1_Load(object sender, EventArgs e)
        {

        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_BASIC_INFORMATION
        {
            public uint ExitStatus;
            public IntPtr PebBaseAddress; // Zero if 32 bit process try get info about 64 bit process 
            public IntPtr AffinityMask;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        private static extern uint NtQueryInformationProcess(
            IntPtr ProcessHandle,
            uint ProcessInformationClass,
            ref PROCESS_BASIC_INFORMATION ProcessInformation,
            int ProcessInformationLength,
            out int ReturnLength
            ); 

        public static string  parrent(int id)
            {
            using (var process = Process.GetProcessById(id))
            {
                var pbi = new PROCESS_BASIC_INFORMATION();
                int writed;

                if (0 != NtQueryInformationProcess(process.Handle, 0, ref pbi, Marshal.SizeOf(pbi), out writed) ||
                     writed == 0)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                string a;
                a= String.Format("{0}", pbi.InheritedFromUniqueProcessId);
              

               

               // MessageBox.Show(a);
                return a;

            }

           }


        public static string GetProcessInfoByPID(int PID, out string User, out string Domain )
        {
            User = String.Empty;
            Domain = String.Empty;
          string OwnerSID = String.Empty;
            string processname = String.Empty;
            try
            {
                ObjectQuery sq = new ObjectQuery
                    ("Select * from Win32_Process Where ProcessID = '" + PID + "'");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(sq);
                if (searcher.Get().Count == 0)
                    return OwnerSID;
                foreach (ManagementObject oReturn in searcher.Get())
                {
                    string[] o = new String[2];
                    //Invoke the method and populate the o var with the user name and domain
                    oReturn.InvokeMethod("GetOwner", (object[])o);

                    //int pid = (int)oReturn["ProcessID"];
                    processname = (string)oReturn["Name"];
                    //dr[2] = oReturn["Description"];
                    User = o[0];
                    if (User == null)
                        User = String.Empty;
                    Domain = o[1];
                    if (Domain == null)
                        Domain = String.Empty;
                    string[] sid = new String[1];
                    oReturn.InvokeMethod("GetOwnerSid", (object[])sid);
                    OwnerSID = sid[0];
                    return OwnerSID;
                }
            }
            catch
            {
                return OwnerSID;
            }
            return OwnerSID;
        }



        public void BrowsApp(string nameApp)
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (identity != null)
            {
                string currentUser = identity.Name.Split('\\')[1];

                string query = "Select * from Win32_Process Where Name = \"" + nameApp + "\"";
                var searcher = new ManagementObjectSearcher(query);
                var processes = searcher.Get();

                foreach (ManagementObject proc in processes)
                {
                    string owner;
                    var argList = new[] { string.Empty };
                    int returnVal = Convert.ToInt32(proc.InvokeMethod("GetOwner", argList));
                    if (returnVal == 0)
                        owner = argList[0];
                    else
                        continue;

                    if (owner != currentUser)
                        continue;

                    MessageBox.Show(proc["ExecutablePath"].ToString());
                }
            }
        }
        
        static bool is64BitProcess = (IntPtr.Size == 8);
        static bool is64BitOperatingSystem = is64BitProcess || InternalCheckIsWow64();

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(
            [In] IntPtr hProcess,
            [Out] out bool wow64Process
        );
        
        public static bool InternalCheckIsWow64()
        {
            try {
                if ((Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor >= 1) ||
                    Environment.OSVersion.Version.Major >= 6)
                {

                    using (Process p = Process.GetProcessById(MyGlobal))
                    {

                        bool retVal;
                        if (!IsWow64Process(p.Handle, out retVal))
                        {
                            return false;
                        }
                        return retVal;
                    }
                }
                else
                {
                    return false;
                }
            }
            catch
            {
                MyGlobal = -1;
                return false;   
            }
        }

        internal int GetProcessIntegrityLevel(int id)
        {
            int IL = -1;
            SafeTokenHandle hToken = null;
            int cbTokenIL = 0;
            IntPtr pTokenIL = IntPtr.Zero;

            try
            {
                // Open the access token of the current process with TOKEN_QUERY.
                if (!NativeMethod.OpenProcessToken(Process.GetProcessById(id).Handle,
                    NativeMethod.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Then we must query the size of the integrity level information 
                // associated with the token. Note that we expect GetTokenInformation 
                // to return false with the ERROR_INSUFFICIENT_BUFFER error code 
                // because we've given it a null buffer. On exit cbTokenIL will tell 
                // the size of the group information.
                if (!NativeMethod.GetTokenInformation(hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0,
                    out cbTokenIL))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != NativeMethod.ERROR_INSUFFICIENT_BUFFER)
                    {
                        // When the process is run on operating systems prior to 
                        // Windows Vista, GetTokenInformation returns false with the 
                        // ERROR_INVALID_PARAMETER error code because 
                        // TokenIntegrityLevel is not supported on those OS's.
                        throw new Win32Exception(error);
                    }
                }

                // Now we allocate a buffer for the integrity level information.
                pTokenIL = Marshal.AllocHGlobal(cbTokenIL);
                if (pTokenIL == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Now we ask for the integrity level information again. This may fail 
                // if an administrator has added this account to an additional group 
                // between our first call to GetTokenInformation and this one.
                if (!NativeMethod.GetTokenInformation(hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTokenIL, cbTokenIL,
                    out cbTokenIL))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Marshal the TOKEN_MANDATORY_LABEL struct from native to .NET object.
                TOKEN_MANDATORY_LABEL tokenIL = (TOKEN_MANDATORY_LABEL)
                    Marshal.PtrToStructure(pTokenIL, typeof(TOKEN_MANDATORY_LABEL));

                // Integrity Level SIDs are in the form of S-1-16-0xXXXX. (e.g. 
                // S-1-16-0x1000 stands for low integrity level SID). There is one 
                // and only one subauthority.
                IntPtr pIL = NativeMethod.GetSidSubAuthority(tokenIL.Label.Sid, 0);
                IL = Marshal.ReadInt32(pIL);
            }
            finally
            {
                // Centralized cleanup for all allocated resources. 
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }
                if (pTokenIL != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pTokenIL);
                    pTokenIL = IntPtr.Zero;
                    cbTokenIL = 0;
                }
            }

            return IL;
        }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {
            // if (listView1.SelectedIndices.Count > 0)

            //  BrowsApp(listView1.Items[listView1.SelectedIndices[0]].ToString());
            // MessageBox.Show(Convert.ToString(listView1.Items[listView1.SelectedIndices[0]]));

            //  string show = Convert.ToString(listView1.Items[listView1.SelectedIndices[0]]);
            string show = String.Format("{0}", listView1.Items[listView1.SelectedIndices[0]]);        
            show = show.Substring(15);
            int a = show.Length;
           show= show.Remove(a-1);
           // MessageBox.Show(show);
            BrowsApp(show);
        }
    

        private void button3_Click(object sender, EventArgs e)
        {
            
                int number = 0;
                var processList = Process.GetProcesses();


                foreach (var proc in processList)
                {
                try
                {
                    ListViewItem lvi = new ListViewItem(String.Format("{0}.exe", proc.ProcessName));

                    lvi.SubItems.Add(String.Format("{0}", proc.Id));

                    string a, b;

                    lvi.SubItems.Add(String.Format("{0}", GetProcessInfoByPID(proc.Id, out a, out b) + "  " + a));
                    try
                    {
                        string s = parrent(proc.Id);
                        number = Convert.ToInt32(s, 10);
                                               
                        try
                        {
                            lvi.SubItems.Add(String.Format(Process.GetProcessById(number).ProcessName + ".exe "+ "("+ number +")"));
                        }
                        catch { lvi.SubItems.Add(String.Format("{0}", " ")); };
                    }
                    catch (Win32Exception)
                    {
                        lvi.SubItems.Add(String.Format("{0}", " "));
                    }
                    MyGlobal = proc.Id;
                    if (InternalCheckIsWow64())
                        lvi.SubItems.Add(String.Format("{0}", "x32"));
                    else if (MyGlobal < 0)
                        lvi.SubItems.Add(String.Format("{0}", " "));
                    else
                        lvi.SubItems.Add(String.Format("{0}", "x64"));
                    try
                    {
                        string sdll="";
                        ProcessModule dll;
                        ProcessModuleCollection myProcessModuleCollection = proc.Modules;
                        for (int i = 1; i < myProcessModuleCollection.Count; i++)
                        {
                            dll = myProcessModuleCollection[i];
                            sdll = sdll + " " + String.Format("{0}", dll.ModuleName);
                          //  lvi.SubItems.Add(String.Format("{0}", dll.ModuleName));

                        }

                        lvi.SubItems.Add(sdll);
                        
                    }
                    catch (Win32Exception) {
                        lvi.SubItems.Add(String.Format("{0}", " "));
                    }
                    try
                    {
                        // Get and display the process integrity level.
                        
                        int IL = GetProcessIntegrityLevel(proc.Id);
                        switch (IL)
                        {
                            case NativeMethod.SECURITY_MANDATORY_UNTRUSTED_RID:
                                lvi.SubItems.Add(String.Format("{0}", "Untrusted")); break;
                            case NativeMethod.SECURITY_MANDATORY_LOW_RID:
                                lvi.SubItems.Add(String.Format("{0}", "Low")); break;
                            case NativeMethod.SECURITY_MANDATORY_MEDIUM_RID:
                                lvi.SubItems.Add(String.Format("{0}", "Medium")); break;
                            case NativeMethod.SECURITY_MANDATORY_HIGH_RID:
                                lvi.SubItems.Add(String.Format("{0}", "High")); break;
                            case NativeMethod.SECURITY_MANDATORY_SYSTEM_RID:
                                lvi.SubItems.Add(String.Format("{0}", "System")); break;
                            default:
                                lvi.SubItems.Add(String.Format("{0}", "Unknown")); break;
                        }
                    }
                    catch (Exception)
                    {
                        lvi.SubItems.Add(String.Format("{0}", "System"));
                    }
                    PrivilegeAndAttributesCollection privileges = proc.GetPrivileges();
                    lvi.SubItems.Add(String.Format("{0}", privileges));
                    listView1.Items.Add(lvi);

                }
                catch { };
                
            }
        }

        private void listView1_SelectedIndexChanged_1(object sender, EventArgs e)
        {

        }

        private void openFileDialog1_FileOk(object sender, CancelEventArgs e)
        {

        }
        private void button1_Click(object sender, EventArgs e)
        {
            int size = -1;
            DialogResult result = openFileDialog1.ShowDialog(); // Show the dialog.
            if (result == DialogResult.OK) // Test result.
            {
                string file = openFileDialog1.FileName;
                try
                {
                    string text = File.ReadAllText(file);
                    size = text.Length;
                }
                catch (IOException)
                {
                }
            }
            Console.WriteLine(size); // <-- Shows file size in debugging mode.
            Console.WriteLine(result); // <-- For debugging use.
        }
    }
}
