using LSAutil;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace LSAutil
{
    public class LSAtool: IDisposable
    {
        private LSA_OBJECT_ATTRIBUTES objectAttributes;
        private LSA_UNICODE_STRING localsystem;
        private LSA_UNICODE_STRING secretName;
        private bool disposedValue;

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaRetrievePrivateData(
          IntPtr PolicyHandle,
          ref LSA_UNICODE_STRING KeyName,
          out IntPtr PrivateData);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaStorePrivateData(
          IntPtr policyHandle,
          ref LSA_UNICODE_STRING KeyName,
          ref LSA_UNICODE_STRING PrivateData);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaOpenPolicy(
          ref LSA_UNICODE_STRING SystemName,
          ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
          uint DesiredAccess,
          out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaNtStatusToWinError(uint status);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaClose(IntPtr policyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaFreeMemory(IntPtr buffer);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">The registry value to encrypt. Use "DefaultPassword"
        /// to encrypt an AutoAdminLogon password.
        /// If AutoAdminLogon is enabled, Windows will first look for DefaultPassword
        /// LSA storage.</param>
        /// <exception cref="Exception"></exception>
        public LSAtool(string key)
        {
            if (key.Length == 0)
                throw new Exception("Key lenght zero");
            this.objectAttributes = new LSA_OBJECT_ATTRIBUTES();
            this.objectAttributes.Length = 0;
            this.objectAttributes.RootDirectory = IntPtr.Zero;
            this.objectAttributes.Attributes = 0U;
            this.objectAttributes.SecurityDescriptor = IntPtr.Zero;
            this.objectAttributes.SecurityQualityOfService = IntPtr.Zero;
            this.localsystem = new LSA_UNICODE_STRING();
            this.localsystem.Buffer = IntPtr.Zero;
            this.localsystem.Length = (ushort)0;
            this.localsystem.MaximumLength = (ushort)0;
            this.secretName = new LSA_UNICODE_STRING();
            this.secretName.Buffer = Marshal.StringToHGlobalUni(key);
            this.secretName.Length = (ushort)(key.Length * 2);
            this.secretName.MaximumLength = (ushort)((key.Length + 1) * 2);
        }

        private IntPtr GetLsaPolicy(LSA_AccessPolicy access)
        {
            IntPtr PolicyHandle;
            uint winError = LsaNtStatusToWinError(LsaOpenPolicy(ref this.localsystem, ref this.objectAttributes, (uint)access, out PolicyHandle));
            if (winError != 0U)
                throw new Exception("LsaOpenPolicy failed: " + (object)winError);
            return PolicyHandle;
        }

        private static void ReleaseLsaPolicy(IntPtr LsaPolicyHandle)
        {
            uint winError = LsaNtStatusToWinError(LsaClose(LsaPolicyHandle));
            if (winError != 0U)
                throw new Exception("LsaClose failed: " + (object)winError);
        }

        private static void FreeMemory(IntPtr Buffer)
        {
            uint winError = LsaNtStatusToWinError(LsaFreeMemory(Buffer));
            if (winError != 0U)
                throw new Exception("LsaFreeMemory failed: " + (object)winError);
        }

        public void SetSecret(string value)
        {
            LSA_UNICODE_STRING PrivateData = new LSA_UNICODE_STRING();
            Console.WriteLine("pass length = {0}", (object)value.Length);
            if (value.Length > 0)
            {
                PrivateData.Buffer = Marshal.StringToHGlobalUni(value);
                PrivateData.Length = (ushort)(value.Length * 2);
                PrivateData.MaximumLength = (ushort)((value.Length + 1) * 2);
            }
            else
            {
                PrivateData.Buffer = IntPtr.Zero;
                PrivateData.Length = (ushort)0;
                PrivateData.MaximumLength = (ushort)0;
            }
            IntPtr lsaPolicy = this.GetLsaPolicy(LSA_AccessPolicy.POLICY_CREATE_SECRET);
            uint status = LsaStorePrivateData(lsaPolicy, ref this.secretName, ref PrivateData);
            ReleaseLsaPolicy(lsaPolicy);
            uint winError = LsaNtStatusToWinError(status);
            if (winError != 0U)
                throw new Exception("StorePrivateData failed: " + (object)winError);
            Console.WriteLine("Set secret password sucessful.");
        }

        public string GetSecret()
        {
            IntPtr PrivateData = IntPtr.Zero;
            IntPtr lsaPolicy = this.GetLsaPolicy(LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION);
            uint status = LsaRetrievePrivateData(lsaPolicy, ref this.secretName, out PrivateData);
            ReleaseLsaPolicy(lsaPolicy);
            uint winError = LsaNtStatusToWinError(status);
            if (winError != 0U)
                throw new Exception("RetreivePrivateData failed: " + (object)winError);
            LSA_UNICODE_STRING structure = (LSA_UNICODE_STRING)Marshal.PtrToStructure(PrivateData, typeof(LSA_UNICODE_STRING));
            string secret = Marshal.PtrToStringAuto(structure.Buffer).Substring(0, (int)structure.Length / 2);
            FreeMemory(PrivateData);
            return secret;
        }

        private struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        private enum LSA_AccessPolicy : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 1,
            POLICY_VIEW_AUDIT_INFORMATION = 2,
            POLICY_GET_PRIVATE_INFORMATION = 4,
            POLICY_TRUST_ADMIN = 8,
            POLICY_CREATE_ACCOUNT = 16, // 0x0000000000000010
            POLICY_CREATE_SECRET = 32, // 0x0000000000000020
            POLICY_CREATE_PRIVILEGE = 64, // 0x0000000000000040
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 128, // 0x0000000000000080
            POLICY_SET_AUDIT_REQUIREMENTS = 256, // 0x0000000000000100
            POLICY_AUDIT_LOG_ADMIN = 512, // 0x0000000000000200
            POLICY_SERVER_ADMIN = 1024, // 0x0000000000000400
            POLICY_LOOKUP_NAMES = 2048, // 0x0000000000000800
            POLICY_NOTIFICATION = 4096, // 0x0000000000001000
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                Marshal.FreeHGlobal(secretName.Buffer);
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~LSAtool()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}


