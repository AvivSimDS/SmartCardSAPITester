using System;
using System.Collections.Generic;
using System.Text;

namespace SmartCardSAPITester
{
    public class SAPIException : ApplicationException
    {
        int _ErrorCode;
        public int ErrorCode
        {
            get { return _ErrorCode; }
        }

        public SAPIException(string Message, int errorCode)
            : base(string.Format(Message + " ({0})", errorCode.ToString("X")))
        {
            _ErrorCode = errorCode;
        }
    }
}
