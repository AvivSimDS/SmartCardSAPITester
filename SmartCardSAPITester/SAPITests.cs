using System;
using System.Collections.Generic;
using System.Text;

using System.Diagnostics;
using System.Threading;
using Microsoft.Win32;

using SAPILib;

namespace SmartCardSAPITester
{
    class SAPITests
    {
        public static SAPIByteArray B64ToSAPIByteArray(ref string B64InputString)
        {
            int B64InpOrgLen = B64InputString.Length;
            B64InputString = B64InputString.Trim('\0');
            B64InputString = B64InputString.Trim();
            int B64InpLen = B64InputString.Length;

            if (B64InpOrgLen != B64InpLen)
                Console.WriteLine(string.Format("B64 Input String was trimmed by {0} characters", B64InpOrgLen - B64InpLen));

            int extraLen = B64InpLen % 4;
            if (extraLen != 0)
            {
                Console.WriteLine(string.Format("removing {0} characters from B64 Input String ", extraLen));
                B64InputString = B64InputString.Remove(B64InpLen - extraLen);
            }
            Console.WriteLine(string.Format("B64 Input String length = '{0}'", B64InputString.Length));
            Console.WriteLine(string.Format("B64 Input String = '{0}'", B64InputString));

            Array signedChalengeBytes = Convert.FromBase64String(B64InputString);
            Console.WriteLine(string.Format("SignedChalengeBytes Input String length = '{0}'", signedChalengeBytes.Length));

            string hexSignedBytes = BitConverter.ToString((byte[])signedChalengeBytes).Replace("-", string.Empty);
            Console.WriteLine("Signed Challenge hex lenght = '" + hexSignedBytes.Length + "'");
            Console.WriteLine("Signed Challenge hex string = '" + hexSignedBytes + "'");

            SAPIByteArray signedChalenge = new SAPIByteArrayClass();
            signedChalenge.FromArray(ref signedChalengeBytes);
            return signedChalenge;
        }

        //////////////////////////////
        // Buffer Signature
        //////////////////////////////
        
        //Sign Buffer (without SC-auth)
        public static void SignBuffer( string Username, 
                                string Domain, 
                                string Password, 
                                byte[] DataToSign, 
                                int DataToSignLen, 
                                ref string Signature, 
                                ref int Result ) 
        {
            //  Call SAPIWrapper for implementation this function...
            try
            {
                //LOG.AddEventLogEntry(string.Format("User {0} has requested to sign buffer", Username), EventLogEntryType.Information);
                Console.WriteLine(string.Format("User {0} has requested to sign buffer", Username));

                SAPIWrapper.SAPI_SignBuffer(
                    Username,
                    /*General.GetCoSignDomain(*/Domain/*)*/,
                    Password,
                    DataToSign,
                    DataToSignLen,
                    ref Signature);

                Result = 0;
                return;

            }
            catch (SAPIException ex)
            {
                Console.WriteLine(string.Format("Failed to sign the buffer by user {0}. Exception:{1}", Username, ex.Message));

                Result = ex.ErrorCode;
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Failed to sign the bufer by user {0}. Exception:{1}", Username, ex.Message));

                Result = -1;
                return;
            }
		}


        //Sign Buffer (without SC-auth) and with Prompt for Sign
        public static void SignBufferEx(string Username, 
                                 string Domain, 
                                 string Password, 
                                 string SigPassword, 
                                 byte[] DataToSign, 
                                 int DataToSignLen, 
                                 ref string Signature, 
                                 ref int Result)
        {
            try
            {
                Console.WriteLine(string.Format("User {0} has requested to sign buffer (prompt for sign)", Username));
                Console.WriteLine(string.Format("SignBufferEx: password = '{0}', sigPassword = '{1}'", Password.ToUpper(), SigPassword.ToUpper()));

                SAPIWrapper.SAPI_SignBufferEx(  Username,
                                                Domain,
                                                Password,
                                                SigPassword,
                                                DataToSign,
                                                DataToSignLen,
                                                ref Signature   );

                Result = 0;
                return;
            }
            catch (SAPIException ex)
            {
                Console.WriteLine(string.Format("Failed to sign the buffer by user {0}. Exception:{1}", Username, ex.Message));

                Result = ex.ErrorCode;
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Failed to sign the bufer by user {0}. Exception:\n{1}", Username, ex.Message));

                Result = -1;
                return;
            }
        }

        
        //Sign Buffer (with SC-auth)
        public static void SignBufferSC(string UPN,             //userName from user prompt or UPN from SC
                                        string Domain,
                                        string LogonPass,       //if Null --> SCLoggon using SignedB64Chall
                                        string SignedB64Chall,
                                        byte[] DataToSign, 
                                        int DataToSignLen, 
                                        ref string Signature,
                                        ref int Result)
        {
            //  Call SAPIWrapper for implementation this function...
            try
            {
                //LOG.AddEventLogEntry(string.Format("User {0} has requested to sign buffer (smart card)", UPN), EventLogEntryType.Information);
                Console.WriteLine(string.Format("User {0} has requested to sign buffer (smart card)", UPN));
                SAPIByteArray signedChalenge = B64ToSAPIByteArray(ref SignedB64Chall);
                Console.WriteLine(string.Format("User {0} has converted SignedB64Challenge to SAPIByteArray. Calling SAPI_SignBufferEx", UPN));

                Object ActualLoggonPassword = LogonPass;
                if (ActualLoggonPassword == null)
                    ActualLoggonPassword = signedChalenge;
                else
                    Console.WriteLine(string.Format("User {0} has passed in loggon password. using it in SAPI_SignBufferEx", UPN));


                SAPIWrapper.SAPI_SignBufferEx(UPN,
                                              Domain,
                                              ActualLoggonPassword,
                                              signedChalenge,
                                              DataToSign,
                                              DataToSignLen,
                                              ref Signature);

                Result = 0;
                return;
            }
            catch (SAPIException ex)
            {
                Console.WriteLine(string.Format("Failed to sign the buffer by user {0}. Exception:\n{1}", UPN, ex.Message));
                Result = ex.ErrorCode;
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Failed to sign the buffer by user {0}. Exception:\n{1}", UPN, ex.Message));
                Result = -1;
                return;
            }
        }



        //Verify Buffer
        public static void VerifyBuffer(byte[] Buffer, 
                                 int BufferLen, 
                                 string Signature, 
                                 ref int isValid, 
                                 ref string Signer, 
                                 ref int Result)
        {
            try
            {
                Console.WriteLine(string.Format("Request to verify buffer"));

                SAPIWrapper.SAPI_VerifyBuffer(Buffer,
                                              BufferLen,
                                              Signature,
                                              ref isValid,
                                              ref Signer);

                Result = 0;
                return;

            }
            catch (SAPIException ex)
            {
                Console.WriteLine(string.Format("Failed to verify the buffer. Exception:{0}", ex.Message));

                Result = ex.ErrorCode;
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Failed to verify the buffer. Exception:\n{0}", ex.Message));

                Result = -1;
                return;
            }
        }


        //Sign PDF file (without SC-auth)
        public static void SignPDF(string UserName,
                            string Domain,
                            string Password,
                            string FileName,
                            int Invisible,
                            int page,
                            int x,
                            int y,
                            int height,
                            int width,
                            string Reason,
                            int isDisplayGraphSig,
                            int isDisplayUsername,
                            int isDisplayDateTime,
                            ref int Result)
        {
            try
            {
                Console.WriteLine(string.Format("User {0} has requested to sign document {1}", UserName, FileName));

                int flag = 0;
                if (isDisplayDateTime != 0) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_TIME;
                if (isDisplayGraphSig != 0) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_GRAPHICAL_IMAGE;
                if (isDisplayUsername != 0) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_SIGNED_BY;
                Reason = (string.IsNullOrEmpty(Reason)) ? null : Reason;
                if (Reason != null) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_REASON;

                SAPIWrapper.SAPI_SignPDF(FileName,
                                         UserName,
                                         Domain,
                                         Password,
                                         page,
                                         x,
                                         y,
                                         height,
                                         width,
                                         Invisible != 0,
                                         Reason,
                                         flag);

                Result = 0;
                return;

            }
            catch (SAPIException ex)
            {
                Console.WriteLine(string.Format("Failed to sign the document by user {0}. Exception:\n{1}", UserName, ex.Message));

                Result = ex.ErrorCode;
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Failed to sign the document by user {0}. Exception:\n{1}", UserName, ex.Message));

                Result = -1;
                return;
            }
        }


        //Sign PDF file (without SC-auth) and with Prompt For Sign
        public static void SignPDFEx(string UserName,
                              string Domain,
                              string Password, 
                              string SigPassword,
                              string FileName,
                              int Invisible,
                              int page,
                              int x,
                              int y,
                              int height,
                              int width,
                              string Reason,
                              int isDisplayGraphSig,
                              int isDisplayUsername,
                              int isDisplayDateTime,
                              ref int Result)
        {
            try
            {
                Console.WriteLine(string.Format("User {0} has requested to sign document with prompt for sign password {1}", UserName, FileName));

                int flag = 0;
                if (isDisplayDateTime != 0) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_TIME;
                if (isDisplayGraphSig != 0) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_GRAPHICAL_IMAGE;
                if (isDisplayUsername != 0) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_SIGNED_BY;
                
                Reason = (string.IsNullOrEmpty(Reason)) ? null : Reason;
                if (Reason != null) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_REASON;
                
                SAPIWrapper.SAPI_SignPDFEx( FileName,
                                            UserName,
                                            Domain,
                                            Password,
                                            SigPassword,
                                            page,
                                            x,
                                            y,
                                            height,
                                            width,
                                            Invisible != 0,
                                            Reason,
                                            flag );

                Result = 0;
                return;
            }
            catch (SAPIException ex)
            {
                Console.WriteLine(string.Format("Failed to sign the document by user {0}. Exception:{1}", UserName, ex.Message));

                Result = ex.ErrorCode;
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Failed to sign the document by user {0}. Exception:{1}", UserName, ex.Message));

                Result = -1;
                return;
            }
        }

        //Sign PDF file (with SC-auth)
        public static void SignPDFSC(string UPN, 
                                     string Domain,
                                     string LogonPass,       //if Null --> SCLoggon using SignedB64Chall
                                     string SignedB64Chall,
                                     string FileName, 
                                     int Invisible, 
                                     int page, 
                                     int x, 
                                     int y,
                                     int height, 
                                     int width,
                                     string Reason,
                                     int isDisplayGraphSig,
                                     int isDisplayUsername,
                                     int isDisplayDateTime,
                                     ref int Result)
        {
            try
            {
                Console.WriteLine(string.Format("SignPDFSC: User {0} has requested to sign document {1}", UPN, FileName));
                SAPIByteArray signedChalenge = B64ToSAPIByteArray(ref SignedB64Chall);
                Console.WriteLine(string.Format("User {0} has converted SignedB64Challenge to SAPIByteArray. Calling SAPI_SignPDFEx", UPN));

                Object ActualLoggonPassword = LogonPass;
                if (ActualLoggonPassword == null)
                    ActualLoggonPassword = signedChalenge;
                else
                    Console.WriteLine(string.Format("User {0} has passed in loggon password. using it in SAPI_SignPDFEx", UPN));

                int flag = 0;
                if (isDisplayDateTime != 0) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_TIME;
                if (isDisplayGraphSig != 0) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_GRAPHICAL_IMAGE;
                if (isDisplayUsername != 0) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_SIGNED_BY;
                
                Reason = (string.IsNullOrEmpty(Reason)) ? null : Reason;
                if (Reason != null) flag |= SAPIWrapper.SAPI_ENUM_DRAWING_ELEMENT_REASON;
                
                SAPIWrapper.SAPI_SignPDFEx(FileName,
                                           UPN,
                                           Domain,
                                           ActualLoggonPassword,
                                           signedChalenge,
                                           page,
                                           x,
                                           y,
                                           height,
                                           width,
                                           Invisible != 0,
                                           Reason,
                                           flag);

                Result = 0;
                return;

            }
            catch (SAPIException ex)
            {
                Console.WriteLine(string.Format("Failed to sign the document by user {0}. Exception:\n{1}", UPN, ex.Message));

                Result = ex.ErrorCode;
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Failed to sign the document by user {0}. Exception:\n{1}", UPN, ex.Message));

                Result = -1;
                return;
            }
        }


        //  Verify a PDF file
        public static void VerifyPDF(string FileName, ref int SignaturesStatus, ref string Signer, ref int Result)
        {
            try
            {
                Console.WriteLine(string.Format("User {0} has requested to verify document {1}", Signer, FileName));

                SAPIWrapper.SAPI_VerifyPDF(
                    FileName,
                    ref SignaturesStatus,
                    ref Result);

                return;
            }
            catch (SAPIException ex)
            {
                Console.WriteLine(string.Format("Failed to verify the document by user {0}. Exception:\n{1}", Signer, ex.Message));

                Result = ex.ErrorCode;
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Failed to sign the document by user {0}. Exception:\n{1}", Signer, ex.Message));

                Result = -1;
                return;
            }
        }


        ////////////////////////////////////
        // SC - auth
        ////////////////////////////////////
        public static void GetChallenge(ref string B64Chall, ref int Result)
        {
            SAPIWrapper.SAPI_GetChallenge(ref B64Chall, ref Result);
        }

    }
}
