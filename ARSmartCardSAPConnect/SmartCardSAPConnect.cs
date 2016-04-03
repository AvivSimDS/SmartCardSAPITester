using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;

using Microsoft.Win32;

using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;


namespace ARSmartCardSAPConnect
{
    public static class LOG
    {
        public const string REG_ROOT = @"HKEY_LOCAL_MACHINE\SOFTWARE\ARL\ARSmartCardSAPConnect";
        public const string REG_VAL_LOGDEST = "LogDest";

        static object sync = new object();

        public static void AddLine(string[] LogLines)
        {
            if (LogLines != null)
                for (int i = 0; i < LogLines.Length; i++)
                    AddLine(LogLines[i]);
        }

        public static void AddLine(string LogLine)
        {
            string LogDest = GetLogDestination();
            if (LogDest == null) return;

            StringBuilder sb = new StringBuilder();
            sb.Append(DateTime.Now.ToShortDateString() + " | ");
            sb.Append(DateTime.Now.ToLongTimeString() + " | ");
            sb.Append(Process.GetCurrentProcess().Id.ToString() + " | ");
            sb.Append(System.Threading.Thread.CurrentThread.ManagedThreadId.ToString() + " | ");
            sb.Append(LogLine);

            try
            {
                lock (sync)
                {
                    StreamWriter fs = File.AppendText(LogDest);
                    fs.WriteLine(sb.ToString());
                    fs.Close();
                }
            }
            catch 
            {
            }

            return;
        }

        private static string GetLogDestination()
        {
            string LogDest = (string)Registry.GetValue(REG_ROOT, REG_VAL_LOGDEST, null);
            return LogDest;
        }

        public static bool Enabled
        {
            get
            {
                return GetLogDestination() == null ? false : true;
            }
        }
    }


    [ComVisible(true)]
    [Guid(@"D4DA2324-8267-4F1A-970F-0D77B748EFE1")]
    [InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    public interface ISmartCardSAPConnect
    {
        [DispId(1)]
        string LastError { get; /*set;*/ }

        [DispId(2)]
        int SignChallenge(string CertIssuer, string B64Challenge, string NameDomainSeparator, ref string B64SignedChallenge, ref string CertSignerUPN);

        [DispId(3)]
        string SignChallengeVBS(string CertIssuer, string B64Challenge, string NameDomainSeparator);

        [DispId(4)]
        string SignChallengeB64VBS(string B64CertIssuer, string B64Challenge, string B64NameDomainSeparator);
    }

    [ComVisible(true)]
    [ProgId(@"ARSmartCardSAPConnect.SmartCardSAPConnect")]
    [Guid(@"2B08C8D0-5FB0-4704-85BC-FD1656054C02")]
    [ClassInterface(ClassInterfaceType.None)]
    public class SmartCardSAPConnect : ISmartCardSAPConnect
    {
        public SmartCardSAPConnect()
        {
            string[] LogLinesTitle = new string[] { "Store Init", "Enum Certs", "Select Cert", "Prepare CMS", "Sign Cert", "Find UPN"};
            LOG.AddLine(String.Format("{0,14}{1,14}{2,14}{3,14}{4,14}{5,14}", LogLinesTitle));
        }
        
        private string _LastError = string.Empty;
        
        public string LastError
        {
            get { return _LastError; }
            //set { m_textProp = value; }
        }

        public int SignChallenge(string CertIssuer, string B64Challenge, string NameDomainSeparator, ref string B64SignedChallenge, ref string CertSignerUPN)
        {
            LOG.AddLine(String.Format("SignChallenge(CertIssuer='{0}',B64Challenge='{1}',NameDomainSeparator='{2}')", CertIssuer, B64Challenge, NameDomainSeparator));
            B64SignedChallenge = "";
            CertSignerUPN = "";

            Stopwatch stopWatch = new Stopwatch();
            long[] tsMeasurments = new long[6];

            //Store Init
            InitStopWatch(ref stopWatch);
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            MeasureAndLogDuration(ref stopWatch, tsMeasurments, 0);

            //Enum Certs
            InitStopWatch(ref stopWatch);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection collection = store.Certificates;
            MeasureAndLogDuration(ref stopWatch, tsMeasurments, 1);

            //Select Cert
            InitStopWatch(ref stopWatch);
            bool userCertFound = false;
            X509Certificate2 cert = null;
            //  Select user's authentication certificate
            foreach (X509Certificate2 cert_i in collection)
            {
                string IssuerNameToUpper = cert_i.IssuerName.Name.ToUpper();
                if (cert_i.IssuerName.Name.Contains(CertIssuer) || IssuerNameToUpper.Contains(CertIssuer))
                {
                    userCertFound = true;
                    cert = cert_i;
                    break;
                }
            }
            MeasureAndLogDuration(ref stopWatch, tsMeasurments, 2);

            if (!userCertFound)
            {
                _LastError = "Certificate with issuer '" + CertIssuer + "' not found in local store";
                return -1;
            }

            //Prepare CMS
            InitStopWatch(ref stopWatch);
            ContentInfo info = new ContentInfo(Convert.FromBase64String(B64Challenge));
            SignedCms cms = new SignedCms(info, false);
            CmsSigner signer = new CmsSigner(SubjectIdentifierType.SubjectKeyIdentifier, cert);
            MeasureAndLogDuration(ref stopWatch, tsMeasurments, 3);

            //Sign Cert
            InitStopWatch(ref stopWatch);
            cms.ComputeSignature(signer, false);
            byte[] signedBytes = cms.Encode();
            LOG.AddLine("Signed Challenge byte lenght = '" + signedBytes.Length + "'");
            string hexSignedBytes = BitConverter.ToString(signedBytes).Replace("-", string.Empty);
            LOG.AddLine("Signed Challenge hex lenght = '" + hexSignedBytes.Length + "'");
            LOG.AddLine("Signed Challenge hex string = '" + hexSignedBytes + "'");
            B64SignedChallenge = Convert.ToBase64String(signedBytes);
            LOG.AddLine("Signed Challenge B64 length = '" + B64SignedChallenge.Length + "'");
            LOG.AddLine("Signed Challenge B64 string = '" + B64SignedChallenge + "'");

            MeasureAndLogDuration(ref stopWatch, tsMeasurments, 4);

            //Find UPN
            InitStopWatch(ref stopWatch);
            foreach (X509Extension ext_j in cert.Extensions)
            {
                if (ext_j.Oid.Value.Equals(/* SAN OID */"2.5.29.17")) //subject alternative name
                {
                    String SAN = ext_j.Format(false);
                    SAN.Trim();
                    CertSignerUPN = SAN.Substring(SAN.LastIndexOf("Principal Name=") + 15);
                    if (!String.IsNullOrEmpty(NameDomainSeparator))
                    {
                        int nameLength = CertSignerUPN.IndexOf(NameDomainSeparator);
                        if (nameLength > 0)
                            CertSignerUPN = CertSignerUPN.Substring(0, nameLength);
                    }
                    break;
                }
            }
            LOG.AddLine("CertSignerUPN = '" + CertSignerUPN + "'");

            MeasureAndLogDuration(ref stopWatch, tsMeasurments, 5);

            return 0;
        }

        private static void MeasureAndLogDuration(ref Stopwatch stopWatch, long[] tsMeasurments, int mIndex)
        {
            stopWatch.Stop();
            tsMeasurments[mIndex] = stopWatch.ElapsedMilliseconds;
            LogMeasurments(tsMeasurments);
        }

        private static void InitStopWatch(ref Stopwatch stopWatch)
        {
            stopWatch.Reset();
            stopWatch.Start();
        }

        private static void LogMeasurments(long[] tsMeasurments)
        {
            var builder = new StringBuilder();
            for (int i = 0; i < 6; i++)
                builder.AppendFormat("{0,14}", tsMeasurments[i]);
            LOG.AddLine(builder.ToString());
        }

        //VBScript COM client compatible
        public string SignChallengeVBS(string CertIssuer, string B64Challenge, string NameDomainSeparator)
        {
            string B64SignedChallenge = "";
            string CertSignerUPN = "";

            int ret = SignChallenge(CertIssuer, B64Challenge, NameDomainSeparator, ref B64SignedChallenge, ref CertSignerUPN);
            
            return CertSignerUPN + ":" + B64SignedChallenge;
        }

        //VBScript COM client compatible - all input strings are in base64 format
        public string SignChallengeB64VBS(string B64CertIssuer, string B64Challenge, string B64NameDomainSeparator)
        {
            byte[] B64CertIssuerData = Convert.FromBase64String(B64CertIssuer);
            string CertIssuer = Encoding.UTF8.GetString(B64CertIssuerData);

            byte[] B64NameDomainSeparatorData = Convert.FromBase64String(B64NameDomainSeparator);
            string NameDomainSeparator = Encoding.UTF8.GetString(B64NameDomainSeparatorData);

            return SignChallengeVBS(CertIssuer, B64Challenge, NameDomainSeparator);
        }


    }
}
