using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Threading;

using Microsoft.Win32;

using ARSmartCardSAPConnect;
using SAPILib;


namespace SmartCardSAPITester
{
    public struct TestData
    {
        public string user;
        public string pass;
        public string sigPass;
        public string domain;
        public int nTimes;
        public string fileName;
        public int invisible;
        public int page;
        public int x;
        public int y;
        public int height;
        public int width;
        public string reason;
        public int isDisplayGraphSig;
        public int isDisplayUsername;
        public int isDisplayDateTime;

        public TestData(string USER,
                        string PASS,
                        string SIGPASS,
                        string DOMAIN,
                        int NTIMES,
                        string FILENAME,
                        int INVISIBLE,
                        int PAGE,
                        int X,
                        int Y,
                        int HEIGHT,
                        int WIDTH,
                        string REASON,
                        int ISDISPLAYGRAPHSIG,
                        int ISDISPLAYUSERNAME,
                        int ISDISPLAYDATETIME)
        {
            user = USER;
            pass = PASS;
            sigPass = SIGPASS;
            domain = DOMAIN;
            nTimes = NTIMES;
            fileName = FILENAME;
            invisible = INVISIBLE;
            page = PAGE;
            x = X;
            y = Y;
            height = HEIGHT;
            width = WIDTH;
            reason = REASON;
            isDisplayGraphSig = ISDISPLAYGRAPHSIG;
            isDisplayUsername = ISDISPLAYUSERNAME;
            isDisplayDateTime = ISDISPLAYDATETIME;
        }
    }

    class Program
    {
        static int Result = 0;

        static void Main(string[] args)
        {
            if ((args == null) || args.Length < 3)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("Usage: SmartCardSAPITester.exe User1:Pass1:SigPass1 User2:Pass2:SigPass2 Domain [Repetitions=1] [Threads=1] [FileName=challenge] [Invisible=0] [page=1] [x=100] [y=100] [height=100] [width=200] [Reason=''] [isDisplayGraphSig=1] [isDisplayUsername=1] [isDisplayDateTime=1]");
                return;
            }

            string User1Data = args[0];      //sharon@chox.local
            string User1;
            string Pass1;
            string SigPass1;
            ParseUserCredentials(User1Data, out User1, out Pass1, out SigPass1);
            Console.WriteLine("User1='" + User1 + "'");
            Console.WriteLine("Pass1='" + Pass1 + "'");
            Console.WriteLine("SigPass1='" + SigPass1 + "'");

            string User2Data = args[1];
            string User2;
            string Pass2;
            string SigPass2;
            ParseUserCredentials(User2Data, out User2, out Pass2, out SigPass2);
            Console.WriteLine("User2='" + User2 + "'");
            Console.WriteLine("Pass2='" + Pass2 + "'");
            Console.WriteLine("SigPass2='" + SigPass2 + "'");

            string Domain = args[2];
            Console.WriteLine("Domain='" + Domain + "'");

            int nTimes = 1;
            if (args.Length > 3)
                nTimes = Int32.Parse(args[3]);

            int nThreads = 1;
            if (args.Length > 4)
                nThreads = Int32.Parse(args[4]);

            string FileName = "challenge";
            if (args.Length > 5)
                FileName = args[5];

            int Invisible = 0;
            if (args.Length > 6)
                Invisible = Int32.Parse(args[6]);

            int page = 1;
            if (args.Length > 7)
                page = Int32.Parse(args[7]);

            int x = 100;
            if (args.Length > 8)
                x = Int32.Parse(args[8]);

            int y = 100;
            if (args.Length > 9)
                y = Int32.Parse(args[9]);

            int height = 100;
            if (args.Length > 10)
                height = Int32.Parse(args[10]);

            int width = 200;
            if (args.Length > 11)
                width = Int32.Parse(args[11]);

            string Reason = "";
            if (args.Length > 12)
                Reason = args[12];

            int isDisplayGraphSig = 1;
            if (args.Length > 13)
                isDisplayGraphSig = Int32.Parse(args[13]);

            int isDisplayUsername = 1;
            if (args.Length > 14)
                isDisplayUsername = Int32.Parse(args[14]);

            int isDisplayDateTime = 1;
            if (args.Length > 15)
                isDisplayDateTime = Int32.Parse(args[15]);

            //prepare array of 2 argument sets
            TestData[] TestDataArray = {
                new TestData(User1, Pass1, SigPass1, Domain, nTimes, FileName, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime),
                new TestData(User2, Pass2, SigPass2, Domain, nTimes, FileName, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime)
            };

            if (nThreads > 1)
            {
                ManualResetEvent resetEvent = new ManualResetEvent(false);
                int toProcess = nThreads;

                // Start workers.
                for (int i = 0; i < nThreads; i++)
                {
                    new Thread(delegate()
                    {
                        Console.WriteLine(Thread.CurrentThread.ManagedThreadId);

                        PerformTest(TestDataArray[Thread.CurrentThread.ManagedThreadId % 2]);

                        // If we're the last thread, signal
                        if (Interlocked.Decrement(ref toProcess) == 0)
                            resetEvent.Set();
                    }).Start();
                }

                // Wait for workers.
                resetEvent.WaitOne();
                Console.WriteLine("Finished.");
            }
            else
                for (int i = 0; i < 2; i++)
                    PerformTest(TestDataArray[i]);
        }

        private static void ParseUserCredentials(string UserData, out string User, out string Pass, out string SigPass)
        {
            User = UserData;
            Pass = "";
            SigPass = "";
            string[] UserPass2Tokens = UserData.Split(':');
            if (UserPass2Tokens.Length >= 2)
            {
                User = UserPass2Tokens[0];
                Pass = UserPass2Tokens[1];
                if (UserPass2Tokens.Length >= 3)
                    SigPass = UserPass2Tokens[2];
            }

        }

        public static void PerformTest(string UserName, string Domain, int nTimes, string FileName, string Password, string SigPassword, int Invisible, int page, int x, int y, int height, int width, string Reason, int isDisplayGraphSig, int isDisplayUsername, int isDisplayDateTime)
        {
            if (string.IsNullOrEmpty(UserName))
            {
                Console.WriteLine(" <- PerformTest (UserName=''). EXIT TEST");
                return;
            }
            if (string.Compare(FileName, "challenge", true) == 0)
                TestSignChallenge(UserName, nTimes);
            else if (File.Exists(FileName))
                TestSignVerifyPDF(UserName, Domain, nTimes, FileName, Password, SigPassword, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime);
            else
                TestSignVerifyBuffer(UserName, Domain, nTimes, Password, SigPassword);
        }

        public static void PerformTest(TestData testData)
        {
            PerformTest(testData.user, testData.domain, testData.nTimes, testData.fileName, testData.pass, testData.sigPass, testData.invisible, testData.page, testData.x, testData.y, testData.height, testData.width, testData.reason, testData.isDisplayGraphSig, testData.isDisplayUsername, testData.isDisplayDateTime);
        }

        private static string ShrinkSignedChall(string B64SignedChall)
        {
            if (string.IsNullOrEmpty(B64SignedChall))
                return B64SignedChall;
            return (B64SignedChall.Substring(0, 10) + "...");
        }

        private static void TestSignChallenge(string UserName, int nTimes)
        {
            string SignerUPN = "";
            String b64SignedChallenge = TestGetSignChallenge(UserName, nTimes, ref SignerUPN);
            Console.WriteLine(string.Format(" <- TestGetSignChallenge (UserName='{0}', Password='{1}')", SignerUPN, ShrinkSignedChall(b64SignedChallenge)));
        }

        private static void TestSignVerifyPDF(string UserName, string Domain, int nTimes, string FileName, string Password, string SigPassword, int Invisible, int page, int x, int y, int height, int width, string Reason, int isDisplayGraphSig, int isDisplayUsername, int isDisplayDateTime)
        {
            for (int i = 0; i < nTimes; i++)
            {
                string SignerUPN = "";
                if (Password == "SC")
                {
                    String b64SignedChallenge = TestGetSignChallenge(UserName, 1, ref SignerUPN);

                    Console.WriteLine(string.Format(" -> SignPDFSC (UserName='{0}', Domain='{1}', Password='{2}', FileName='{3}', Invisible={4}, page={5}, x={6}, y={7}, height={8}, width={9}, Reason='{10}', isDisplayGraphSig={11}, isDisplayUsername={12}, isDisplayDateTime={13})",
                        SignerUPN, Domain, ShrinkSignedChall(b64SignedChallenge), FileName, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime));

                    SAPITests.SignPDFSC(SignerUPN, Domain, null, b64SignedChallenge, FileName, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime, ref Result);

                    Console.WriteLine(string.Format("{0:X} <- SignPDFSC (...)", Result));

                }
                else if (String.IsNullOrEmpty(SigPassword))
                {
                    Console.WriteLine(string.Format(" -> SignPDF (UserName='{0}', Domain='{1}', Password='{2}', FileName='{3}', Invisible={4}, page={5}, x={6}, y={7}, height={8}, width={9}, Reason='{10}', isDisplayGraphSig={11}, isDisplayUsername={12}, isDisplayDateTime={13})",
                        UserName, Domain, Password, FileName, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime));

                    SAPITests.SignPDF(UserName, Domain, Password, FileName, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime, ref Result);

                    Console.WriteLine(string.Format("{0:X} <- SignPDF (...)", Result));
                }
                else if (SigPassword == "SC")
                {
                    String b64SignedChallenge = TestGetSignChallenge(UserName, 1, ref SignerUPN);

                    Console.WriteLine(string.Format(" -> SignPDFSC (UserName='{0}', Domain='{1}', Password='{2}', SigPass='{3}', FileName='{4}', Invisible={5}, page={6}, x={7}, y={8}, height={9}, width={10}, Reason='{11}', isDisplayGraphSig={12}, isDisplayUsername={13}, isDisplayDateTime={13})",
                        SignerUPN, Domain, Password, ShrinkSignedChall(b64SignedChallenge), FileName, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime));

                    SAPITests.SignPDFSC(SignerUPN, Domain, Password, b64SignedChallenge, FileName, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime, ref Result);

                    Console.WriteLine(string.Format("{0:X} <- SignPDFSC (...)", Result));
                }
                else
                {
                    Console.WriteLine(string.Format(" -> SignPDFEx (UserName='{0}', Domain='{1}', Password='{2}', SigPassword='{3}', FileName='{4}', Invisible={5}, page={6}, x={7}, y={8}, height={9}, width={10}, Reason='{11}', isDisplayGraphSig={12}, isDisplayUsername={13}, isDisplayDateTime={14})",
                        UserName, Domain, Password, SigPassword, FileName, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime));

                    SAPITests.SignPDFEx(UserName, Domain, Password, SigPassword, FileName, Invisible, page, x, y, height, width, Reason, isDisplayGraphSig, isDisplayUsername, isDisplayDateTime, ref Result);

                    Console.WriteLine(string.Format("{0:X} <- SignPDFEx (...)", Result));
                }
            }

            //Verify the signed document - only once to save testing time
            int SignaturesStatus = 0;
            string Signer = "";
            Console.WriteLine(string.Format(" -> VerifyPDF (FileName='{0}')", FileName));

            SAPITests.VerifyPDF(FileName, ref SignaturesStatus, ref Signer, ref Result);

            Console.WriteLine(string.Format("Result={0:X} SignaturesStatus={1} Signer='{2}' <- debug_VerifyPDF (...)", Result, SignaturesStatus, Signer));

        }

        private static String TestGetSignChallenge(string UserName, int nTimes, ref string SignerUPN)
        {
            String b64Challenge = "";
            Console.WriteLine(string.Format(" -> GetChallenge (ref b64Challenge='{0}', ref Result='{1}')", b64Challenge, Result));
            SAPITests.GetChallenge(ref b64Challenge, ref Result);
            Console.WriteLine(string.Format("{0:X} '{1}' <- GetChallenge()", Result, b64Challenge));

            String IssuerName = UserName;    //chox-TECHLAB15-CA
            String b64SignedChallenge = "";
            SignerUPN = "";

            SmartCardSAPConnect scSAP = new SmartCardSAPConnect();

            String UserAndchall = "";
            for (int i = 0; i < nTimes; i++)
            {
                //Result = scSAP.SignChallenge(IssuerName, b64Challenge, "," /* "@" */, ref b64SignedChallenge, ref SignerUPN);
                Console.WriteLine(string.Format(" -> SignChallenge (Issuer='{0}', b64Challenge='{1}', out b64SignedChallenge='{2}', out SignerUPN='{3}')", IssuerName, b64Challenge, b64SignedChallenge, SignerUPN));
                UserAndchall = scSAP.SignChallengeVBS(IssuerName, b64Challenge, ",");
                string[] tokens = UserAndchall.Split(':');
                if (tokens.Length < 2)
                {
                    Console.WriteLine("ERROR: less than 2 tokens in return of scSAP.SignChallengeVBS");
                    SignerUPN = "";
                    b64SignedChallenge = UserAndchall;
                }
                else
                {
                    SignerUPN = tokens[0];
                    b64SignedChallenge = tokens[1];
                }

            }

            Console.WriteLine(string.Format("{0:X} UPN={1} SignedChall='{2}' <- SignChallenge()", Result, SignerUPN, ShrinkSignedChall(b64SignedChallenge)));

            return b64SignedChallenge;
        }

        private static void TestSignVerifyBuffer(string UserName, string Domain, int nTimes, string Password, string SigPassword)
        {
            byte[] DataToSign = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            string Signature = "";

            for (int i = 0; i < nTimes; i++)
            {
                string SignerUPN = "";
                if (Password == "SC")
                {
                    String b64SignedChallenge = TestGetSignChallenge(UserName, 1, ref SignerUPN);

                    Console.WriteLine(string.Format(" -> SignBufferSC (UserName='{0}', Domain='{1}', b64SignedChallenge='{2}', DataToSign={3}, DataToSign.Length={4})",
                        SignerUPN, Domain, ShrinkSignedChall(b64SignedChallenge), DataToSign.ToString(), DataToSign.Length));
                    SAPITests.SignBufferSC(SignerUPN, Domain, null, b64SignedChallenge, DataToSign, DataToSign.Length, ref Signature, ref Result);

                    Console.WriteLine(string.Format("{0:X} Signature='{1}' <- SignBufferSC ()", Result, Signature));
                }
                else if (String.IsNullOrEmpty(SigPassword))
                {
                    Console.WriteLine(string.Format(" -> SignBuffer (UserName='{0}', Domain='{1}', Password='{2}', DataToSign={3}, DataToSign.Length={4})",
                        UserName, Domain, Password, DataToSign.ToString(), DataToSign.Length));

                    SAPITests.SignBuffer(UserName, Domain, Password, DataToSign, DataToSign.Length, ref Signature, ref Result);

                    Console.WriteLine(string.Format("{0:X} <- SignBuffer (...)", Result));
                }
                else if (SigPassword == "SC")
                {
                    String b64SignedChallenge = TestGetSignChallenge(UserName, 1, ref SignerUPN);

                    Console.WriteLine(string.Format(" -> SignBufferSC (UserName='{0}', Password='{1}', Domain='{2}', b64SignedChallenge='{3}', DataToSign={4}, DataToSign.Length={5})",
                        SignerUPN, Password, Domain, ShrinkSignedChall(b64SignedChallenge), DataToSign.ToString(), DataToSign.Length));

                    SAPITests.SignBufferSC(SignerUPN, Domain, Password, b64SignedChallenge, DataToSign, DataToSign.Length, ref Signature, ref Result);

                    Console.WriteLine(string.Format("{0:X} <- SignBufferEx (...)", Result));
                }
                else
                {
                    Console.WriteLine(string.Format(" -> SignBufferEx (UserName='{0}', Domain='{1}', Password='{2}', SigPassword={3}, DataToSign={4}, DataToSign.Length={5})",
                        UserName, Domain, Password, SigPassword, DataToSign.ToString(), DataToSign.Length));

                    SAPITests.SignBufferEx(UserName, Domain, Password, SigPassword, DataToSign, DataToSign.Length, ref Signature, ref Result);

                    Console.WriteLine(string.Format("{0:X} <- SignBufferEx (...)", Result));
                }
            }

            //Verify the signed buffer - only once to save testing time
            int isValid = 0;
            string Signer = "";
            Console.WriteLine(string.Format(" -> VerifyBuffer (Buffer='{0}', Buffer.Length={1}, Signature='{2}')", DataToSign.ToString(), DataToSign.Length, Signature));
            SAPITests.VerifyBuffer(DataToSign, DataToSign.Length, Signature, ref isValid, ref Signer, ref Result);
            Console.WriteLine(string.Format("Result={0:X} isValid={1} Signer='{2}' <- VerifyBuffer (...)", Result, isValid, Signer));
        }
    }
}
