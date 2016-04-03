using System;
using System.Collections.Generic;
using System.Text;

//using ARSmartCardSAPConnect;
using SAPILib;

namespace SmartCardSAPITester
{
    internal static class SAPIWrapper
    {
        public const int SAPI_ENUM_DRAWING_ELEMENT_GRAPHICAL_IMAGE = 0x00000001;
        public const int SAPI_ENUM_DRAWING_ELEMENT_SIGNED_BY = 0x00000002;
        public const int SAPI_ENUM_DRAWING_ELEMENT_REASON = 0x00000004;
        public const int SAPI_ENUM_DRAWING_ELEMENT_TIME = 0x00000008;

        private static System.Object lockThis = new System.Object();
        private static SAPICrypt SAPI = null;

        private static SAPICrypt SAPIInit()
        {
            Console.WriteLine("SAPIInit():");
            lock (lockThis)
            {
                // Access thread-sensitive resources.
                if (SAPI == null)
                {
                    try
                    {
                        SAPI = new SAPICryptClass();
                        int rc = SAPI.Init();
                        if (rc != 0)
                        {
                            Console.WriteLine("Failed in SAPIInit: " + rc.ToString("X"));
                            Console.WriteLine("SAPIInit():Return(ERROR)");
                            SAPI = null;
                            throw new SAPIException("Failed to initialize SAPI", rc);
                        }

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Failed to instantiate SAPICOM: " + ex.ToString());
                        Console.WriteLine("SAPIInit():Return(ERROR)");
                        throw ex;
                    }
                }
            }

            return SAPI;
        }

        private static void LogPassword(String PassType, Object Password)
        {
            if (Password == null)
                Console.WriteLine(PassType + ": NULL");
            else if (Password.GetType().FullName.Equals("System.String", StringComparison.InvariantCultureIgnoreCase))
                Console.WriteLine(PassType + ": '" + (String)Password + "'");
            else
                Console.WriteLine(PassType + ": SIGNED CHALLENGE");
        }

        //
        //  Sign Bufer
        //
        public static void SAPI_SignBuffer(
            string Username,
            string Domain,
            string Password,
            byte[] DataToSign,
            int DataToSignLen,
            ref string Signature)
        {
            Console.WriteLine("SAPI_SignBuffer():");
            SAPI_SignBufferEx(Username, Domain, Password, "", DataToSign, DataToSignLen, ref Signature);
        }


        //
        //  SignBufferEx
        //
        public static void SAPI_SignBufferEx(
            string User,
            string Domain,
            Object Password,
            Object SigPassword,
            byte[] DataToSign,
            int DataToSignLen,
            ref string Signature)
        {
            Console.WriteLine("SAPI_SignBufferEx():");
            Console.WriteLine("Username: '" + (string.IsNullOrEmpty(User) ? "NULL" : User) + "'");
            Console.WriteLine("Domain: '" + (string.IsNullOrEmpty(Domain) ? "NULL" : Domain) + "'");
            LogPassword("Logon Password", Password);
            LogPassword("Sig Password", SigPassword);
            Console.WriteLine("DataToSign (len):" + DataToSignLen.ToString());

            try
            {
                SAPICrypt SAPI = SAPIInit();

                int rc;
                SESHandle SesHandle;
                if ((rc = SAPI.HandleAcquire(out SesHandle)) != 0)
                {
                    Console.WriteLine("Failed in SAPIHandleAcquire() with rc = " + rc.ToString("X"));
                    throw new SAPIException("Failed to allocate SAPI Session Handle", rc);
                }

                //Logon
                rc = SAPI_Logon(User, Domain, Password, SesHandle, SAPI);

                Console.WriteLine("Before temporary buffer allocation");
                //Build SAPI-Compatible bytes array
                Array chunk = new byte[DataToSignLen];
                chunk = DataToSign;
                SAPIByteArray tmpBuff = new SAPIByteArrayClass();
                tmpBuff.FromArray(ref chunk);
                SAPIByteArray csn_sig = new SAPIByteArrayClass();

                rc = SAPI_SignBuffer(SAPI, SesHandle, SigPassword, tmpBuff, csn_sig);

                // Return the value of the signature in the parameter
                byte[] tmpSig = (byte[])csn_sig.ToArray();
                Signature = Convert.ToBase64String(tmpSig);

                SAPI.Logoff(SesHandle);
                SAPI.HandleRelease(SesHandle);

                Console.WriteLine("SignatureLen:" + Signature.Length);
                Console.WriteLine("SAPI_SignBufferEx():Return(OK)");
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: " + ex.ToString());
                Console.WriteLine("SAPI_SignBufferEx():Return(ERROR)");
                throw;
            }
        }

        private static int SAPI_SignBuffer(SAPICrypt SAPI, SESHandle SesHandle, Object SigPassword, SAPIByteArray BuffToSign, SAPIByteArray SigBuff)
        {
            int rc = -1;

            if (SigPassword.GetType().FullName.Equals("System.String", StringComparison.InvariantCultureIgnoreCase))
            {
                String sigPassword = (String)SigPassword;
                if (string.IsNullOrEmpty(sigPassword))
                {
                    Console.WriteLine("Before SAPIBufferSign()");
                    rc = SAPI.BufferSign(SesHandle,
                                         BuffToSign,
                                         SigBuff,
                                         0);
                }
                else
                {
                    Console.WriteLine("Before SAPIBufferSignEx()");
                    rc = SAPI.BufferSignEx(SesHandle,
                                           BuffToSign,
                                           SigBuff,
                                           0,
                                           sigPassword);
                }
            }
            else
            {
                Console.WriteLine("Before SAPIBufferSignEx2()");
                rc = SAPI.BufferSignEx2(SesHandle,
                                       BuffToSign,
                                       SigBuff,
                                       0,
                                       (SAPIByteArray)SigPassword);
            }

            if (rc != 0)
            {
                SAPI.Logoff(SesHandle);
                SAPI.HandleRelease(SesHandle);
                Console.WriteLine("Failed in SAPIBufferSign() with rc = " + rc.ToString("X"));
                throw new SAPIException("Failed to sign buffer", rc);
            }
            return rc;
        }

        private static string TrimWSAndNulls(string InputString)
        {
            string trimmedStr = InputString;
            trimmedStr = trimmedStr.Trim('\0');
            trimmedStr = trimmedStr.Trim();
            return trimmedStr;
        }

        private static int SAPI_SetCoSignUserAccountCertificateAsDefault(SESHandle SesHandle, SAPICrypt SAPI)
        {
            int rc = -1;
            /*
            CertHandle _cert = new CertHandleClass();
            rc = SAPI.CertificateGUISelect(SesHandle, 0, out _cert);
            */
           return rc;
        }

        private static int SAPI_Logon(string User, string Domain, Object Password, SESHandle SesHandle, SAPICrypt SAPI)
        {
            int rc = -1;

            //try to bind Specific Appliance to SAPI session
            //BindSAPISessionToAppliance(Password, SesHandle, SAPI);

            Console.WriteLine(" ==>> SAPI_Logon: User is '" + Domain + "\\" + User + "'");
            User = TrimWSAndNulls(User);
            Domain = TrimWSAndNulls(Domain);

            if (Password.GetType().FullName.Equals("System.String", StringComparison.InvariantCultureIgnoreCase))
            {
                if ((String)Password != "SSPI")
                {
                    Console.WriteLine("SAPI.Logon(UP) to CoSign appliance. User is '" + Domain + "\\" + User + "'");
                    rc = SAPI.Logon(SesHandle, User, Domain, (String)Password);
                }
                else
                {
                    Console.WriteLine("Logged ON (SSPI) to CoSign appliance. User is '" + Domain + "\\" + User + "'");
                    rc = 0;
                }
            }
            else
            {
                Console.WriteLine("SAPI.LogonEx2(SC) to CoSign appliance. User is '" + Domain + "\\" + User + "'");
                rc = SAPI.LogonEx2(SesHandle, User, Domain, (SAPIByteArray)Password, 0);
            }

            if (rc != 0)
            {
                SAPI.HandleRelease(SesHandle);

                if (((uint)rc) == 0x900201E0)
                {
                    SAPI.HandleRelease(SesHandle);
                    Console.WriteLine("Failed to Logon: Wrong Credentials!");
                    throw new SAPIException("Failed to authenticate the user: username/password doesn't match", rc);
                }
                else if (rc != 0)
                {
                    Console.WriteLine("Failed in SAPILogon with rc = " + rc.ToString("X"));
                    throw new SAPIException("Failed to authenticate the user", rc);
                }
            }
            return rc;
        }

        //private static int BindSAPISessionToAppliance(Object Password, SESHandle SesHandle, SAPICrypt SAPI)
        //{
        //    int rc = -1;
        //    string SpecificAppliance = General.GetSpecificAppliance(Password);
        //    if (!string.IsNullOrEmpty(SpecificAppliance))
        //    {
        //        Console.WriteLine("Binding SAPI session to specific CoSign appliance = " + SpecificAppliance);
        //        lock (lockThis)
        //        {
        //            rc = SAPI.SetTokenID(SesHandle, SpecificAppliance);
        //        }
        //        if (rc == 0)
        //            Console.WriteLine("SAPI.SetTokenID to specific CoSign appliance = '" + SpecificAppliance + "' is successful");
        //        else
        //            Console.WriteLine("Failed in SAPI.SetTokenID with rc = " + rc.ToString("X"));
        //    }
        //    else
        //        Console.WriteLine("SmartCard/UserPass appliance is null or empty in registry. SAPI->SetTokenID not called.");

        //    return rc;
        //}


        //
        //  VerifyBuffer
        //
        public static void SAPI_VerifyBuffer(
            byte[] Buffer,
            int BufferLen,
            string Signature,
            ref int isValid,
            ref string Signer)
        {
            Console.WriteLine("SAPI_VerifyBuffer():");
            Console.WriteLine("Buffer (len):" + BufferLen);
            Console.WriteLine("Signature:" + Signature);
            Console.WriteLine("SignatureLen:" + Signature.Length);

            //Default is invalid
            isValid = 0;
            try
            {
                SAPICrypt SAPI = SAPIInit();

                int rc;
                SESHandle SesHandle;
                //SigFieldHandle sf = null;

                if ((rc = SAPI.HandleAcquire(out SesHandle)) != 0)
                {
                    Console.WriteLine("Failed in SAPIHandleAcquire() with rc = " + rc.ToString("X"));
                    throw new SAPIException("Failed to allocate SAPI Session Handle", rc);
                }

                SAPIByteArray csn_sig = SAPITests.B64ToSAPIByteArray(ref Signature);

                // get the certificate:
                Object Cert;
                SAPI_ENUM_DATA_TYPE Type = SAPI_ENUM_DATA_TYPE.SAPI_ENUM_DATA_TYPE_NONE;
                if ((rc = SAPI.PKCS7BlobGetValue(SesHandle, csn_sig, SAPI_ENUM_PKCS7_FIELD.SAPI_ENUM_PKCS7_FIELD_CERT, out Cert, ref Type)) != 0)
                {
                    SAPI.HandleRelease(SesHandle);
                    Console.WriteLine("Error on SAPI.PKCS7BlobGetValue, rc = " + rc);
                    throw new SAPIException("Error on SAPI.PKCS7BlobGetValue", rc);
                }

                // get the name of the signer (Subject)
                Object Subject;
                Type = SAPI_ENUM_DATA_TYPE.SAPI_ENUM_DATA_TYPE_NONE;
                if ((rc = SAPI.CertificateGetFieldByBlob(SesHandle, (SAPIByteArray)Cert, SAPI_ENUM_CERT_FIELD.SAPI_ENUM_CERT_FIELD_SUBJECT, out Subject, ref Type)) != 0)
                {
                    SAPI.HandleRelease(SesHandle);
                    Console.WriteLine("Error on SAPI.CertificateGetFieldByBlob, rc = " + rc);
                    throw new SAPIException("Error on SAPI.CertificateGetFieldByBlob, rc = ", rc);
                }
                Signer = (string)Subject;

                Console.WriteLine("Before temporary buffer allocation");
                Array chunk = new byte[BufferLen];
                chunk = Buffer;
                SAPIByteArray SAPIBuff = new SAPIByteArrayClass();
                SAPIBuff.FromArray(ref chunk);
                // VERIFY:
                SAPIFileTime SignTime = new SAPIFileTimeClass();  // do not do anything with the time now...
                CertStatus CertStatus = new CertStatusClass();
                if ((rc = SAPI.BufferVerifySignature(SesHandle, SAPIBuff, csn_sig, SignTime, CertStatus, 0)) != 0)
                {
                    SAPI.HandleRelease(SesHandle);
                    isValid = 0;
                    Console.WriteLine("Error on SAPI.BufferVerifySignature, rc = " + rc);
                    throw new SAPIException("Error on SAPI.BufferVerifySignature, rc = ", rc);
                }

                //SAPI.HandleRelease(sf);
                SAPI.HandleRelease(SesHandle);
                isValid = 1;

                Console.WriteLine("SAPI_VerifyBuffer():Return(OK)");
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: " + ex.ToString());
                Console.WriteLine("SAPI_VerifyBuffer():Return(ERROR)");
                throw;
            }
        }


        public static void SAPI_SignPDF(
            string FileName,
            string User,
            string Domain,
            Object Password,
            int page,
            int x,
            int y,
            int height,
            int width,
            bool Invisible,
            string Reason,
            int AppearanceMask)
        {
            Console.WriteLine("SAPI_SignPDF()");
            SAPI_SignPDFEx(
                FileName,
                User,
                Domain,
                Password,
                "",
                page,
                x,
                y,
                height,
                width,
                Invisible,
                Reason,
                AppearanceMask);

            return;
        }

        // This function is thread-safe and could be called by a few threads simultaneously.
        // If FieldName parameter is NULL, a new field will be created, otherwise existing field will be signed
        // and all field-related parameters will be ignored
        public static void SAPI_SignPDFEx(
            string FileName,
            string User,
            string Domain,
            Object Password,
            Object SigPassword,
            int page,
            int x,
            int y,
            int height,
            int width,
            bool Invisible,
            string Reason,
            int AppearanceMask)
        {
            Console.WriteLine("SAPI_SignPDFEx():");
            Console.WriteLine("FileName: " + (string.IsNullOrEmpty(FileName) ? "NULL" : FileName));
            Console.WriteLine("Username: " + (string.IsNullOrEmpty(User) ? "NULL" : User));
            Console.WriteLine("Domain: " + (string.IsNullOrEmpty(Domain) ? "NULL" : Domain));
            LogPassword("Logon Password", Password);
            LogPassword("Sig Password", SigPassword);
            Console.WriteLine("Page: " + page.ToString());
            Console.WriteLine("X: " + x.ToString());
            Console.WriteLine("Y: " + y.ToString());
            Console.WriteLine("height: " + height.ToString());
            Console.WriteLine("width: " + width.ToString());
            Console.WriteLine("invisible: " + Invisible.ToString());
            Console.WriteLine("Reason: " + Reason);
            Console.WriteLine("Appearance Mask: " + AppearanceMask.ToString("X"));
            //Console.WriteLine("Date Format: " + General.getSapiDateFormat());
            //Console.WriteLine("Time Format: " + General.getSapiTimeFormat());

            try
            {
                SAPICrypt SAPI = SAPIInit();

                int rc;
                SESHandle SesHandle;
                if ((rc = SAPI.HandleAcquire(out SesHandle)) != 0)
                {
                    Console.WriteLine("Failed in SAPIHandleAcquire() with rc = " + rc.ToString("X"));
                    throw new SAPIException("Failed to allocate SAPI Session Handle", rc);
                }

                //turn all PDF signatures to be PADES
                rc = SAPI.ConfigurationValueSet(SesHandle, SAPI_ENUM_CONF_ID.SAPI_ENUM_CONF_ID_PADES_ENABLE, SAPI_ENUM_DATA_TYPE.SAPI_ENUM_DATA_TYPE_DWORD, (int)1, 1);
                Console.WriteLine(" ==>> SAPI.ConfigurationValueSet(SAPI_ENUM_CONF_ID_PADES_ENABLE): rc = '" + rc + "'");

                //Logon
                rc = SAPI_Logon(User, Domain, Password, SesHandle, SAPI);

                SigFieldSettings SFS = new SigFieldSettingsClass();
                TimeFormat TF = new TimeFormatClass();
                int Flags = 0;

                if (Invisible)
                {
                    SFS.Invisible = 1;
                    SFS.Page = -1;
                }
                else
                {
                    // VISIBLE:
                    SFS.Invisible = 0;
                    // location:
                    SFS.Page = page;
                    SFS.X = x;
                    SFS.Y = y;
                    SFS.Height = height;
                    SFS.Width = width;
                    // appearance:
                    SFS.AppearanceMask = AppearanceMask;
                    SFS.LabelsMask = 0;
                    SFS.DependencyMode = SAPI_ENUM_DEPENDENCY_MODE.SAPI_ENUM_DEPENDENCY_MODE_INDEPENDENT;
                    SFS.SignatureType = SAPI_ENUM_SIGNATURE_TYPE.SAPI_ENUM_SIGNATURE_DIGITAL;
                    SFS.Flags = 0;
                    // time:
                    TF.DateFormat = "MMM d yyyy";
                    TF.TimeFormat = "h:mm tt";
                    TF.ExtTimeFormat = SAPI_ENUM_EXTENDED_TIME_FORMAT.SAPI_ENUM_EXTENDED_TIME_FORMAT_GMT;
                    SFS.TimeFormat = TF;
                }

                //Create the Field
                SigFieldHandle sf = null;
                if ((rc = SAPI.SignatureFieldCreate(SesHandle, SAPI_ENUM_FILE_TYPE.SAPI_ENUM_FILE_ADOBE,
                    FileName, SFS, Flags, out sf)) != 0)
                {
                    SAPI.Logoff(SesHandle);
                    SAPI.HandleRelease(SesHandle);
                    Console.WriteLine("Failed in SAPISignatureFieldCreate() with rc = " + rc.ToString("X"));
                    throw new SAPIException("Failed to create signature field", rc);
                }

                //Define the Reason
                if (Reason != null)
                {
                    if ((rc = SAPI.ConfigurationValueSet(SesHandle, SAPI_ENUM_CONF_ID.SAPI_ENUM_CONF_ID_REASON,
                        SAPI_ENUM_DATA_TYPE.SAPI_ENUM_DATA_TYPE_STR, Reason, 1)) != 0)
                    {
                        SAPI.HandleRelease(sf);
                        SAPI.Logoff(SesHandle);
                        SAPI.HandleRelease(SesHandle);
                        Console.WriteLine("Failed in SAPIConfigurationValueSet with rc = " + rc.ToString("X"));
                        throw new SAPIException("Failed to define signing reason", rc);
                    }
                }

                rc = SAPI_SignField(SAPI, SesHandle, sf, SigPassword);

                SAPI.Logoff(SesHandle);
                SAPI.HandleRelease(sf);
                SAPI.HandleRelease(SesHandle);

                Console.WriteLine("SAPI_SignPDF():Return(OK)");
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: " + ex.ToString());
                Console.WriteLine("SAPI_SignPDF():Return(ERROR)");
                throw;
            }
        }

        private static int SAPI_SignField(SAPICrypt SAPI, SESHandle SesHandle, SigFieldHandle sf, Object SigPassword)
        {
            int rc = -1;
            if (SigPassword.GetType().FullName.Equals("System.String", StringComparison.InvariantCultureIgnoreCase))
            {
                String sigPassword = (String)SigPassword;
                if (string.IsNullOrEmpty(sigPassword))
                {
                    Console.WriteLine("Before SAPI.SignatureFieldSign()");
                    rc = SAPI.SignatureFieldSign(SesHandle, sf, 0);
                }
                else
                {
                    Console.WriteLine("Before SAPI.SignatureFieldSignEx()");
                    rc = SAPI.SignatureFieldSignEx(SesHandle, sf, 0, sigPassword);
                }
            }
            else
            {
                Console.WriteLine("Before SAPI.SignatureFieldSignEx2()");
                rc = SAPI.SignatureFieldSignEx2(SesHandle, sf, 0, (SAPIByteArray)SigPassword);
            }

            if (rc != 0)
            {
                SAPI.HandleRelease(sf);
                SAPI.Logoff(SesHandle);
                SAPI.HandleRelease(SesHandle);
                Console.WriteLine("Failed in SAPISignatureFieldSign() with rc = " + rc.ToString("X"));
                throw new SAPIException("Failed to sign Signature Field", rc);
            }
            return rc;
        }

        private const int ERROR_ENCOUNTERED = -1;
        private const int ALL_VALID_SIGNATURES = 0;         //all fields are signed, all signatures valid
        private const int SOME_VALID_SIGNATURES = 1;        //some fields are signed, all signatures valid
        private const int SOME_INVALID_SIGNATURES = 2;      //some fields are signed, some signatures invalid
        private const int NO_SIGNATURES = 3;                //there are no signatures on the document (there might be fields)

        public static void SAPI_VerifyPDF(string FileName, ref int SignaturesStatus, ref int rc)
        {
            Console.WriteLine("in SAPI_VerifyPDF()");
            SignaturesStatus = NO_SIGNATURES;
            rc = 0;
            try
            {
                SESHandle SesHandle;
                SigFieldHandle sf = null;
                CertStatus status = new CertStatus();
                int NumOfFields = 0;
                int signedFields = 0;
                int unsignedFields = 0;
                int okSignedFields = 0;
                int badSignedFields = 0;

                SAPICrypt SAPI = SAPIInit();

                Console.WriteLine("SAPI.HandleAcquire");
                if ((rc = SAPI.HandleAcquire(out SesHandle)) != 0)
                {
                    Console.WriteLine("Failed in SAPIHandleAcquire() with rc = " + rc.ToString("X"));
                    SignaturesStatus = ERROR_ENCOUNTERED;
                    return;
                }

                SAPIContext ctxField = new SAPIContextClass();

                //Initiate the Signature Fields enumeration process
                Console.WriteLine("SAPI.SignatureFieldEnumInit");
                if ((rc = SAPI.SignatureFieldEnumInit(SesHandle, ctxField, SAPI_ENUM_FILE_TYPE.SAPI_ENUM_FILE_ADOBE,
                    FileName, 0, ref NumOfFields)) != 0)
                {
                    SAPI.Logoff(SesHandle);
                    SAPI.HandleRelease(SesHandle);
                    Console.WriteLine("Failed in SignatureFieldEnumInit() with rc = " + rc.ToString("X"));
                    SignaturesStatus = ERROR_ENCOUNTERED;
                    return;
                }

                if (NumOfFields > 0)
                {
                    SignaturesStatus = ALL_VALID_SIGNATURES;
                }
                else
                {
                    SignaturesStatus = NO_SIGNATURES;
                }


                for (int i = 0; i < NumOfFields; i++)
                {
                    //Get Next field's handle
                    Console.WriteLine("SAPI.SignatureFieldEnumCont");
                    if ((rc = SAPI.SignatureFieldEnumCont(SesHandle, ctxField, out sf)) != 0)
                    {
                        SAPI.ContextRelease(ctxField);
                        SAPI.Logoff(SesHandle);
                        SAPI.HandleRelease(SesHandle);
                        Console.WriteLine("Failed in SignatureFieldEnumCont() with rc = " + rc.ToString("X"));
                        SignaturesStatus = ERROR_ENCOUNTERED;
                        return;
                    }

                    SigFieldSettings settings = new SigFieldSettingsClass();
                    SigFieldInfo sigFieldInfo = new SigFieldInfoClass();

                    Console.WriteLine("SAPI.SignatureFieldInfoGet");
                    rc = SAPI.SignatureFieldInfoGet(SesHandle, sf, settings, sigFieldInfo);
                    if (rc != 0)
                    {
                        SAPI.ContextRelease(ctxField);
                        SAPI.Logoff(SesHandle);
                        SAPI.HandleRelease(SesHandle);
                        Console.WriteLine("Failed in SignatureFieldInfoGet() with rc = " + rc.ToString("X"));
                        SignaturesStatus = ERROR_ENCOUNTERED;
                        return;
                    }

                    string fieldName = settings.Name;

                    if (sigFieldInfo.IsSigned != 0)  //if field is signed, get data
                    {
                        //update signed counter
                        signedFields++;

                        //verify signature
                        Console.WriteLine("SAPI.SignatureFieldVerify");
                        rc = SAPI.SignatureFieldVerify(SesHandle, sf, status, 0);
                        Console.WriteLine("SAPI.SignatureFieldVerify Done");

                        if (rc != 0)
                        {
                            Console.WriteLine("Failed in SignatureFieldVerify() on field #" + i + " with rc = " + rc.ToString("X"));
                            badSignedFields++;
                        }
                        else
                        {
                            if (status.SAPICertStatus == SAPI_ENUM_CERT_STATUS.SAPI_ENUM_CERT_STATUS_NOT_CHECKED)
                            {
                                Console.WriteLine("Certificate status on field #" + i + " = CERT_STATUS_NOT_CHECKED (" + SAPI_ENUM_CERT_STATUS.SAPI_ENUM_CERT_STATUS_NOT_CHECKED + ")");
                                okSignedFields++;
                            }
                            else if (status.SAPICertStatus == SAPI_ENUM_CERT_STATUS.SAPI_ENUM_CERT_STATUS_OK)
                            {
                                Console.WriteLine("Certificate status on field #" + i + " = CERT_STATUS_OK (" + SAPI_ENUM_CERT_STATUS.SAPI_ENUM_CERT_STATUS_OK + ")");
                                okSignedFields++;
                            }
                            else if (status.SAPICertStatus == SAPI_ENUM_CERT_STATUS.SAPI_ENUM_CERT_STATUS_WARNING)
                            {
                                Console.WriteLine("Certificate status on field #" + i + " = CERT_STATUS_WARNING (" + SAPI_ENUM_CERT_STATUS.SAPI_ENUM_CERT_STATUS_WARNING + ")");
                                okSignedFields++;
                            }
                            else if (status.SAPICertStatus == SAPI_ENUM_CERT_STATUS.SAPI_ENUM_CERT_STATUS_REVOKED)
                            {
                                Console.WriteLine("Certificate status on field #" + i + " = CERT_STATUS_REVOKED (" + SAPI_ENUM_CERT_STATUS.SAPI_ENUM_CERT_STATUS_REVOKED + ")");
                                badSignedFields++;
                            }
                            else if (status.SAPICertStatus == SAPI_ENUM_CERT_STATUS.SAPI_ENUM_CERT_STATUS_INVALID)
                            {
                                Console.WriteLine("Certificate status on field #" + i + " = CERT_STATUS_INVALID (" + SAPI_ENUM_CERT_STATUS.SAPI_ENUM_CERT_STATUS_INVALID + ")");
                                badSignedFields++;
                            }
                            else if (status.SAPICertStatus == SAPI_ENUM_CERT_STATUS.SAPI_ENUM_TS_CERT_STATUS_REVOKED)
                            {
                                SignaturesStatus = SOME_INVALID_SIGNATURES;
                                badSignedFields++;
                            }
                            else if (status.SAPICertStatus == SAPI_ENUM_CERT_STATUS.SAPI_ENUM_TS_CERT_STATUS_INVALID)
                            {
                                Console.WriteLine("Certificate status on field #" + i + " = TS_CERT_STATUS_INVALID (" + SAPI_ENUM_CERT_STATUS.SAPI_ENUM_TS_CERT_STATUS_INVALID + ")");
                                badSignedFields++;
                            }
                        }
                    }
                    //field not signed
                    else
                    {
                        Console.WriteLine("field #" + i + " NOT SIGNED");
                        unsignedFields++;
                    }

                    //Release handle of irrelevant signature field
                    SAPI.HandleRelease(sf);
                }

                //all seems finished without errors, summarize SignaturesStatus
                if (NumOfFields > 0)
                {
                    if (signedFields > 0)
                    {
                        if (badSignedFields > 0)
                        {
                            Console.WriteLine("At least 1 signature fields in document '" + FileName + "' is badly signed");
                            Console.WriteLine("SignaturesStatus = SOME_INVALID_SIGNATURES");
                            SignaturesStatus = SOME_INVALID_SIGNATURES;
                        }
                        else
                        {
                            if (signedFields < NumOfFields)
                            {
                                Console.WriteLine("At least 1 signature fields in document '" + FileName + "' is not signed");
                                Console.WriteLine("SignaturesStatus = SOME_VALID_SIGNATURES");
                                SignaturesStatus = SOME_VALID_SIGNATURES;
                            }
                            else
                            {
                                Console.WriteLine("All fields are signed, all signatures valid in document '" + FileName + "'.");
                                Console.WriteLine("SignaturesStatus = ALL_VALID_SIGNATURES");
                                SignaturesStatus = ALL_VALID_SIGNATURES;
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("All signature fields in document '" + FileName + "' are UNSIGNED");
                        Console.WriteLine("SignaturesStatus = NO_SIGNATURES");
                        SignaturesStatus = NO_SIGNATURES;
                    }
                }
                else
                {
                    Console.WriteLine("There are no signature fields in document " + FileName);
                    Console.WriteLine("SignaturesStatus = NO_SIGNATURES");
                    SignaturesStatus = NO_SIGNATURES;
                }

                SAPI.ContextRelease(ctxField);
                SAPI.Logoff(SesHandle);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception in SAPI_VerifyPDF() rc = " + rc.ToString("X") + " : " + ex.Message + "; " + ex.InnerException.Message);
                SignaturesStatus = ERROR_ENCOUNTERED;
            }
        }

        //SmartCard Authentication 15/02/15 avivs
        public static void SAPI_GetChallenge(ref string B64Challenge, ref int Result)
        {
            SESHandle SesHandle;
            int rc;

            SAPICrypt SAPI = SAPIInit();

            Console.WriteLine("SAPI.HandleAcquire");
            if ((rc = SAPI.HandleAcquire(out SesHandle)) != 0)
            {
                Console.WriteLine("Failed in SAPI.HandleAcquire() with rc = " + rc.ToString("X"));
                Result = rc;
                return;
            }

            //try to bind SC Appliance to SAPI session
            //BindSAPISessionToAppliance(null, SesHandle, SAPI);
            //string SCAppliance = General.GetSpecificAppliance(null);
            //Console.WriteLine("Smart card Appliance is '" + SCAppliance + "'");

            // Get challenge - CoSign server time
            TokenInfo tinfo = new TokenInfo();
            Console.WriteLine("SAPI.GetTokenInfo");
            lock (lockThis)
            {
                if ((rc = SAPI.GetTokenInfo(SesHandle, /*SCAppliance*/"", 0, tinfo)) != 0)
                {
                    Console.WriteLine("Failed in SAPI.GetTokenInfo with rc = " + rc.ToString("X"));
                    SAPI.HandleRelease(SesHandle);
                    Result = rc;
                    return;
                }
            }
            Console.WriteLine("SAPI.GetTokenInfo returned TokenTime = " + tinfo.TokenTime.ToString("X"));
            byte[] timeBuf = BitConverter.GetBytes(tinfo.TokenTime);

            B64Challenge = Convert.ToBase64String(timeBuf);
            Console.WriteLine("SAPI_GetChallenge returning B64Challenge = '" + B64Challenge + "'");

            SAPI.HandleRelease(SesHandle);

            Result = 0;
        }
    }

}
