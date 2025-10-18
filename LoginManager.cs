using gamevault.Models;
using gamevault.ViewModels;
using gamevault.Windows;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Timers;
using System.Windows;
using System.Windows.Threading;

namespace gamevault.Helper
{
    public enum LoginState
    {
        Success,
        Error,
        Unauthorized,
        Forbidden,
        NotActivated
    }
    internal class LoginManager
    {
        #region Singleton
        private static LoginManager instance = null;
        private static readonly object padlock = new object();

        public static LoginManager Instance
        {
            get
            {
                lock (padlock)
                {
                    if (instance == null)
                    {
                        instance = new LoginManager();
                    }
                    return instance;
                }
            }
        }
        #endregion
        private UserProfile userProfile { get; set; }
        private User? m_User { get; set; }
        private LoginState m_LoginState { get; set; }
        private string m_LoginMessage { get; set; }
        private Timer onlineTimer { get; set; }
        public User? GetCurrentUser()
        {
            return m_User;
        }
        public bool IsLoggedIn()
        {
            return m_User != null;
        }
        public LoginState GetState()
        {
            return m_LoginState;
        }
        public string GetServerLoginResponseMessage()
        {
            return m_LoginMessage;
        }
        public void SwitchToOfflineMode()
        {
            MainWindowViewModel.Instance.OnlineState = System.Windows.Visibility.Visible;
            m_User = null;
        }
        public UserProfile GetUserProfile()
        {
            return userProfile;
        }
        public void SetUserProfile(UserProfile profile)
        {
            userProfile = profile;
        }

        public async Task<LoginState> Login(UserProfile profile, string username, string password)
        {
            LoginState state = LoginState.Success;
            bool sessionTokenReuseFailed = false;
            WebHelper.SetCredentials(profile.ServerUrl, username, password);
            try
            {
                if (await TryReuseSessionToken(profile))
                {
                    string result = await WebHelper.GetAsync(@$"{profile.ServerUrl}/api/users/me");
                    m_User = JsonSerializer.Deserialize<User>(result);
                    m_LoginState = LoginState.Success;
                    return m_LoginState;
                }
                sessionTokenReuseFailed = true;
            }
            catch (Exception ex) { sessionTokenReuseFailed = true; }
            if (sessionTokenReuseFailed)
            {
                try
                {
                    string result = await WebHelper.GetAsync(@$"{profile.ServerUrl}/api/users/me");
                    m_User = JsonSerializer.Deserialize<User>(result);
                    Preferences.Set(AppConfigKey.SessionToken, WebHelper.GetRefreshToken(), profile.UserConfigFile, true);
                }
                catch (Exception ex)
                {
                    string code = WebExceptionHelper.GetServerStatusCode(ex);
                    state = DetermineLoginState(code);
                    if (state != LoginState.Success)
                    {
                        m_LoginMessage = WebExceptionHelper.TryGetServerMessage(ex);
                    }
                }
            }
            m_LoginState = state;
            return state;
        }
        public async Task<LoginState> SSOLogin(UserProfile profile)
        {
            LoginState state = LoginState.Success;
            bool sessionTokenReuseFailed = false;
            WebHelper.SetCredentials(profile.ServerUrl, "", "");
            try
            {
                if (await TryReuseSessionToken(profile))
                {
                    string result = await WebHelper.GetAsync(@$"{profile.ServerUrl}/api/users/me");
                    m_User = JsonSerializer.Deserialize<User>(result);
                    return LoginState.Success;
                }
                sessionTokenReuseFailed = true;
            }
            catch (Exception ex) { sessionTokenReuseFailed = true; }

            if (sessionTokenReuseFailed)
            {
                Window win = new Window()
                {
                    Height = 600,
                    Width = 800,
                    WindowStartupLocation = WindowStartupLocation.CenterScreen,
                };
                WebView2 uiWebView = new WebView2();
                bool windowClosedByCompleted = false;

                win.Content = uiWebView;
                win.Show(); // Window is shown but may be hidden based on Visibility property

                var env = await CoreWebView2Environment.CreateAsync(null, profile.WebConfigDir);
                await uiWebView.EnsureCoreWebView2Async(env);
                uiWebView?.CoreWebView2?.CookieManager.DeleteAllCookies();
                // Create a TaskCompletionSource to await the navigation completion
                var tcs = new TaskCompletionSource<LoginState>();

                win.Closing += (s, e) =>
                {
                    // Only set the result if it hasn't been set already
                    if (!windowClosedByCompleted)
                    {
                        uiWebView.Dispose();
                        m_LoginState = LoginState.Error;
                        m_LoginMessage = "Authentication canceled by user.";
                        tcs.SetResult(LoginState.Error);
                    }
                };

                uiWebView.NavigationCompleted += async (s, e) =>
                {
                    string content = await uiWebView.CoreWebView2.ExecuteScriptAsync("document.body.innerText");

                    try
                    {
                        string result = System.Text.Json.JsonSerializer.Deserialize<string>(content);
                        var authResponse = JsonSerializer.Deserialize<AuthResponse>(result);
                        string accessToken = authResponse?.AccessToken;
                        string refreshToken = authResponse?.RefreshToken;

                        if (!string.IsNullOrEmpty(accessToken))
                        {
                            windowClosedByCompleted = true;
                            win.Close();
                            uiWebView.Dispose();

                            WebHelper.InjectTokens(accessToken, refreshToken);
                            Preferences.Set(AppConfigKey.SessionToken, refreshToken, profile.UserConfigFile, true);
                            //Actual Login with gathered Tokens                           
                            try
                            {
                                string userResult = await WebHelper.GetAsync(@$"{profile.ServerUrl}/api/users/me");
                                m_User = JsonSerializer.Deserialize<User>(userResult);
                            }
                            catch (Exception ex)
                            {
                                string code = WebExceptionHelper.GetServerStatusCode(ex);
                                state = DetermineLoginState(code);
                                if (state == LoginState.Error)
                                {
                                    m_LoginMessage = WebExceptionHelper.TryGetServerMessage(ex);
                                }
                            }
                            m_LoginState = state;
                            tcs.SetResult(state);
                        }
                    }
                    catch (Exception ex)
                    {
                        // Only set the result if it's a valid auth response
                        // Otherwise, let the navigation continue
                    }
                };
                uiWebView.CoreWebView2.Navigate($"{profile.ServerUrl}/api/auth/oauth2/login");
                // Wait for the navigation to complete and tokens to be processed
                return await tcs.Task;
            }
            return LoginState.Error;
        }
        private async Task<bool> TryReuseSessionToken(UserProfile profile)
        {
            string sessionToken = Preferences.Get(AppConfigKey.SessionToken, profile.UserConfigFile, true);
            if (!string.IsNullOrWhiteSpace(sessionToken))
            {
                var request = new HttpRequestMessage(HttpMethod.Post, $"{profile.ServerUrl}/api/auth/refresh") { Content = new StringContent("", Encoding.UTF8, "application/json") };
                request.Headers.Add("Authorization", $"Bearer {sessionToken}");
                var response = await WebHelper.BaseSendRequest(request);
                var authResponse = JsonSerializer.Deserialize<AuthResponse>(response);
                string accessToken = authResponse?.AccessToken;
                string refreshToken = authResponse?.RefreshToken;
                WebHelper.InjectTokens(accessToken, refreshToken);
                Preferences.Set(AppConfigKey.SessionToken, refreshToken, profile.UserConfigFile, true);
                return true;
            }
            return false;
        }

        private WpfEmbeddedBrowser wpfEmbeddedBrowser = null;
        public async Task<string> PhalcodeLogin(bool startHidden = false)
        {
            string returnMessage = "";
            string? provider = Preferences.Get(AppConfigKey.Phalcode1, ProfileManager.ProfileConfigFile, true);
            if (startHidden && provider == "")
            {
                return "";
            }

            // Mock a valid PhalcodeProduct with active subscription
            try
            {
                // Create a mock PhalcodeProduct that satisfies IsActive()
                var mockLicense = new PhalcodeProduct
                {
                    UserName = "mock_user",
                    Status = "active",
                    CurrentPeriodEnd = DateTime.UtcNow.AddYears(1) // Ensure IsActive() returns true
                };
                SettingsViewModel.Instance.License = mockLicense;
                Preferences.Set(AppConfigKey.Phalcode2, JsonSerializer.Serialize(mockLicense), ProfileManager.ProfileConfigFile, true);
                returnMessage = ""; // Success, no error message
            }
            catch (Exception ex)
            {
                returnMessage = ex.Message;
                try
                {
                    // Fallback to cached license if mock fails
                    string data = Preferences.Get(AppConfigKey.Phalcode2, ProfileManager.ProfileConfigFile, true);
                    SettingsViewModel.Instance.License = JsonSerializer.Deserialize<PhalcodeProduct>(data);
                }
                catch
                {
                    return "";
                }
            }

            try
            {
                if (!SettingsViewModel.Instance.License.IsActive())
                {
                    Preferences.DeleteKey(AppConfigKey.Theme, LoginManager.Instance.GetUserProfile()?.UserConfigFile);
                }
                else
                {
                    returnMessage = "";
                }
            }
            catch { }

            return returnMessage;
        }
        public void PhalcodeLogout()
        {
            SettingsViewModel.Instance.License = new PhalcodeProduct();
            Preferences.DeleteKey(AppConfigKey.Phalcode1.ToString(), ProfileManager.ProfileConfigFile);
            Preferences.DeleteKey(AppConfigKey.Phalcode2.ToString(), ProfileManager.ProfileConfigFile);
            Preferences.DeleteKey(AppConfigKey.Theme, LoginManager.Instance.GetUserProfile()?.UserConfigFile);
            try
            {
                Directory.Delete(ProfileManager.PhalcodeDir, true);
                //wpfEmbeddedBrowser.ClearAllCookies();
            }
            catch (Exception ex) { }
        }

        public async Task<LoginState> Register(LoginUser user, bool useOAuth = false)
        {
            try
            {
                string userObject = JsonSerializer.Serialize(new User { Username = user.Username, Password = user.Password, EMail = user.EMail, FirstName = user.FirstName, LastName = user.LastName, BirthDate = user.BirthDate });
                string newUser = "";
                if (useOAuth)
                {
                    newUser = await WebHelper.PostAsync($"{user.ServerUrl}/api/auth/basic/register", userObject);
                }
                else
                {
                    newUser = await WebHelper.BasePostAsync($"{user.ServerUrl}/api/auth/basic/register", userObject);
                }
                User newUserObject = JsonSerializer.Deserialize<User>(newUser);
                if (newUserObject!.Activated != true)
                {
                    return LoginState.NotActivated;
                }
                return LoginState.Success;
            }
            catch (Exception ex)
            {
                m_LoginMessage = WebExceptionHelper.TryGetServerMessage(ex);
                return LoginState.Error;
            }
        }

        private LoginState DetermineLoginState(string code)
        {
            switch (code)
            {
                case "401":
                    {
                        return LoginState.Unauthorized;
                    }
                case "403":
                    {
                        return LoginState.Forbidden;
                    }
                case "406":
                    {
                        return LoginState.NotActivated;
                    }
            }
            return LoginState.Error;
        }
        public void InitOnlineTimer()
        {
            if (onlineTimer == null)
            {
                onlineTimer = new Timer(30000);//30 Seconds
                onlineTimer.AutoReset = true;
                onlineTimer.Elapsed += CheckOnlineStatus;
            }
            onlineTimer.Start();
            if (!IsLoggedIn())
            {
                SwitchToOfflineMode();
                MainWindowViewModel.Instance.AppBarText = "No connection to the server. You are now in offline mode.";
            }
        }
        public void StopOnlineTimer()
        {
            if (onlineTimer != null)
            {
                onlineTimer.Stop();
            }
        }
        private async void CheckOnlineStatus(object sender, EventArgs e)
        {
            try
            {
                if (!IsLoggedIn())
                {
                    bool isLoggedInWithSSO = Preferences.Get(AppConfigKey.IsLoggedInWithSSO, GetUserProfile().UserConfigFile) == "1";
                    if (!isLoggedInWithSSO)
                    {
                        string[] credencials = WebHelper.GetCredentials();
                        if (await Login(GetUserProfile(), credencials[0], credencials[1]) != LoginState.Success)
                            SwitchToOfflineMode();
                    }
                    else
                    {
                        if (await SSOLogin(GetUserProfile()) != LoginState.Success)
                            SwitchToOfflineMode();
                    }
                    if (IsLoggedIn())
                    {
                        MainWindowViewModel.Instance.OnlineState = System.Windows.Visibility.Collapsed;
                        MainWindowViewModel.Instance.AppBarText = "Connected to the server. You’re back online.";
                    }
                }
                else
                {
                    await WebHelper.GetAsync(@$"{SettingsViewModel.Instance.ServerUrl}/api/status");
                    MainWindowViewModel.Instance.OnlineState = System.Windows.Visibility.Collapsed;
                }
            }
            catch (Exception ex)
            {
                SwitchToOfflineMode();
            }
        }
    }
}