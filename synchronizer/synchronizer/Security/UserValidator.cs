using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Web.Security;
using log4net;

namespace synchronizer.Security {
    public class UserValidator : MembershipProvider {
        private static readonly ILog log = LogManager.GetLogger(typeof(UserValidator));

        [DllImport("ADVAPI32.dll", EntryPoint = "LogonUserW", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        private const string ACL_FILE_NAME = "security\\administration.acl";

        private String _strName;
        private String _strApplicationName;
        private String _userDomain;
        private int _logonType;

        private Boolean _boolEnablePasswordReset;
        private Boolean _boolEnablePasswordRetrieval;
        private int _intMaxInvalidPasswordAttempts;
        private int _intMinRequiredAlphanumericCharacters;
        private int _intMinRequiredPasswordLength;
        private MembershipPasswordFormat _oPasswordFormat;
        private string _strPasswordStrengthRegularExpression;
        private Boolean _boolRequiresQuestionAndAnswer;
        private Boolean _boolRequiresUniqueEMail;

        public UserValidator() {
            _strName = "UserValidator";
            _strApplicationName = "DefaultApp";
            _userDomain = "";
            _logonType = 2; // Interactive by default

            _boolEnablePasswordReset = false;
            _boolEnablePasswordRetrieval = false;
            _boolRequiresQuestionAndAnswer = false;
            _boolRequiresUniqueEMail = false;

            _intMaxInvalidPasswordAttempts = 3;
            _intMinRequiredAlphanumericCharacters = 1;
            _intMinRequiredPasswordLength = 5;
            _strPasswordStrengthRegularExpression = @"[\w| !§$%&amp;/()=\-?\*]*";

            _oPasswordFormat = MembershipPasswordFormat.Clear;
        }

        public override void Initialize(string name, System.Collections.Specialized.NameValueCollection config) {
            if (config == null) {
                throw new ArgumentNullException("config");
            }

            if (string.IsNullOrEmpty(name)) {
                name = "UserValidator";
            }

            if (string.IsNullOrEmpty(config["description"])) {
                config.Remove("description");
                config.Add("description", "UserValidator Membership Provider");
            }

            base.Initialize(name, config);

            foreach (string key in config.Keys) {
                switch (key.ToLower()) {
                    case "name": _strName = config[key]; break;
                    case "applicationname": _strApplicationName = config[key]; break;
                    case "userdomain": _userDomain = config[key]; break;
                    case "logontype": _logonType = int.Parse(config[key]); break;
                }
            }
            using (var stream = File.Create(getAclFile())) {
                string infoText = string.Format(
                    "You can grant or deny access to the application for the given user by setting appropriate permissions to this file.{0}" +
                    "The file content has no matter - the user can log into TFS4JIRA Synchronizer application only when he has both Read and Write access to this file.{0}" +
                    "See: https://confluence.spartez.com/display/TFS4JIRA/Setting+TFS4JIRA+Synchronizer+application+access+permissions for details",
                    Environment.NewLine);

                byte[] buffer = Encoding.UTF8.GetBytes(infoText);
                stream.Write(buffer, 0, buffer.Length);
            }
        }

        public override bool ValidateUser(string strName, string strPassword) {
            bool isAdmin;
            return validateUserAndCheckIfAdmin(strName, _userDomain, strPassword, out isAdmin);
        }

        //this is used a lot  
        public bool validateUserAndCheckIfAdmin(string userName, string domain, string password, out bool isAdmin) {
            var token = IntPtr.Zero;
            var loggedInOk = LogonUser(userName, domain, password, _logonType, 0, ref token);
            isAdmin = false;
            if (loggedInOk) {
                var impersonationContext = WindowsIdentity.Impersonate(token);
                try {
                    using (var fs = new FileStream(getAclFile(), FileMode.Open, FileAccess.ReadWrite)) {
                        isAdmin = true;
                    }
                } catch (Exception e) {
                    log.Debug(e);
                } finally {
                    impersonationContext.Undo();
                }
            }
            return loggedInOk;
        }

        // this is just for displaying a file path in login screen help
        public static string getAclFile() {
            var path = AppDomain.CurrentDomain.GetData("DataDirectory") + "\\" + ACL_FILE_NAME;
            return path;
        }
 
        /**
         * Properties
         */

        public override string ApplicationName {
            get {
                return _strApplicationName;
            }
            set {
                _strApplicationName = value;
            }
        }

        public override string Name {
            get {
                return _strName;
            }
        }
        
        public override bool EnablePasswordReset {
            get {
                return _boolEnablePasswordReset;
            }
        }
        
        public override bool EnablePasswordRetrieval {
            get {
                return _boolEnablePasswordRetrieval;
            }
        }
        public override int MaxInvalidPasswordAttempts {
            get {
                return _intMaxInvalidPasswordAttempts;
            }

        }
        public override int MinRequiredNonAlphanumericCharacters {
            get {
                return _intMinRequiredAlphanumericCharacters;
            }

        }
        public override int MinRequiredPasswordLength {
            get {
                return _intMinRequiredPasswordLength;
            }

        }
        public override int PasswordAttemptWindow {
            get {
                throw new NotImplementedException();
            }
        }
        public override MembershipPasswordFormat PasswordFormat {
            get {
                return _oPasswordFormat;
            }
        }
        public override string PasswordStrengthRegularExpression {
            get {
                return _strPasswordStrengthRegularExpression;
            }
        }
        public override bool RequiresQuestionAndAnswer {
            get {
                return _boolRequiresQuestionAndAnswer;
            }
        }
        public override bool RequiresUniqueEmail {
            get {
                return _boolRequiresUniqueEMail;
            }
        }

        /*
         * API Functions
         */

        public override string GetPassword(string strName, string strAnswer) {
            throw new NotImplementedException();
        }

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion,
                                                  string passwordAnswer, bool isApproved, object userId, out MembershipCreateStatus status) {

            throw new NotImplementedException();
        }

        public override string GetUserNameByEmail(string strEmail) {
            throw new NotImplementedException();
        }

        public override string ResetPassword(string strName, string strAnswer) {
            throw new NotImplementedException();
        }

        public override bool ChangePassword(string strName, string strOldPwd, string strNewPwd) {
            throw new NotImplementedException();
        }

        public override int GetNumberOfUsersOnline() {
            throw new NotImplementedException();
        }

        public override bool ChangePasswordQuestionAndAnswer(string strName, string strPassword, string strNewPwdQuestion, string strNewPwdAnswer) {
            throw new NotImplementedException();
        }

        public override MembershipUser GetUser(string strName, bool boolUserIsOnline) {
            throw new NotImplementedException();
        }

        public override bool DeleteUser(string strName, bool boolDeleteAllRelatedData) {
            throw new NotImplementedException();
        }

        public override MembershipUserCollection FindUsersByEmail(string strEmailToMatch, int iPageIndex, int iPageSize, out int iTotalRecords) {
            throw new NotImplementedException();
        }
        public override MembershipUserCollection FindUsersByName(string strUsernameToMatch, int iPageIndex, int iPageSize, out int iTotalRecords) {
            throw new NotImplementedException();
        }

        public override MembershipUserCollection GetAllUsers(int iPageIndex, int iPageSize, out int iTotalRecords) {
            throw new NotImplementedException();
        }

        public override void UpdateUser(MembershipUser user) {
            throw new NotImplementedException();
        }

        public override bool UnlockUser(string strUserName) {
            throw new NotImplementedException();
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline) {
            throw new NotImplementedException();
        }
    }
}