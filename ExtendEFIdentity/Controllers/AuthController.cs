using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ExtendEFIdentity.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using ExtendEFIdentity.Entities;
using Microsoft.AspNetCore.Authorization;
using System.IO;
using System.Security.Claims;

namespace ExtendEFIdentity.Controllers
{
    public class AuthController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;


        public AuthController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {

                    AppUser appUser = new AppUser
                    {
                        FullName = model.FullName,
                        UserName = model.Email,
                        Email = model.Email
                    };
                    var createResult = await _userManager.CreateAsync(appUser, model.Password);
                    if (createResult.Succeeded)
                    {
                        IdentityResult addClaimResult;
                        //assign reader type claim
                        if (appUser.Email.EndsWith("reader.com", StringComparison.InvariantCultureIgnoreCase))
                        {
                            addClaimResult = await _userManager.AddClaimAsync(appUser, new Claim("type", "READER"));
                        }
                        //assign general type claim
                        else
                        {
                            addClaimResult = await _userManager.AddClaimAsync(appUser, new Claim("type", "GENERAL"));
                        }

                        string confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(appUser);
                        string confirmEmailUrl = Url.Action(nameof(ConfirmEmail), "Auth", new { id = appUser.Id, token = confirmationToken }, Request.Scheme);

                        //send your email here....
                        System.IO.File.WriteAllText("AccountActivation.txt", confirmEmailUrl);


                        return RedirectToAction(nameof(CheckYourEmail), new { reason = CheckEmailEnum.Registration });

                    }
                    else
                    {
                        return View("Error", createResult.Errors.Select(c => c.Description).ToList());
                    }
                }
                catch (Exception ex)
                {
                    List<string> errors = new List<string>();
                    Exception current = ex;
                    while (current != null)
                    {
                        errors.Add(current.Message);
                        current = current.InnerException;
                    }
                    return View("Error", errors);
                }
            }
            return View(model);
        }

        public async Task<IActionResult> Login()
        {
            LoginViewModel loginViewModel = new LoginViewModel();
            var loginProviders = await _signInManager.GetExternalAuthenticationSchemesAsync();
            if (loginProviders != null && loginProviders.Any())
            {
                loginViewModel.ExternalLoginProviders.AddRange(
                        loginProviders.Select(c => c.Name)
                    );
            }
            return View(loginViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {

            try
            {
                if (ModelState.IsValid)
                {
                    var user = await _userManager.FindByNameAsync(model.Email);
                    if (user != null)
                    {
                        if (!user.EmailConfirmed)
                        {
                            return View("Error", new List<string>
                            {
                                "Your account must be activated first!"
                            });
                        }
                        if (!user.TwoFactorEnabled)
                        {
                            return await CommonLogin(user, model.Password);
                        }
                        else
                        {
                            return RedirectToAction(nameof(TwoFactorLoginHandler), new { email = model.Email });
                        }
                    }
                    ModelState.AddModelError("", "Invalid username or password");
                }
            }
            catch (Exception ex)
            {
                List<string> errors = new List<string>();
                Exception current = ex;
                while (current != null)
                {
                    errors.Add(current.Message);
                    current = current.InnerException;
                }
                return View("Error", errors);
            }
            return View(model);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider)
        {
            string callback = Url.Action(nameof(ExternalLoginCallback));
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = callback,
                Items =
                {
                    {AppConstants.LoginProviderItemKey,provider }
                }
            }, provider);
        }
        public async Task<IActionResult> ExternalLoginCallback()
        {
            //if you use this technique, make sure to include LoginProvider key in the Auth Props Items
            var externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();

            //if you don't wanna use the technique above, you can use this one
            //var authenticationResult = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
            if (externalLoginInfo != null)
            {
                var user = await _userManager.FindByLoginAsync(externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey);
                if (user != null)
                {
                    var signInResult = await _signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey, true);
                    if (signInResult.Succeeded)
                    {
                        return RedirectToAction("Index", "Home");
                    }
                    else if (signInResult.RequiresTwoFactor)
                    {
                        return RedirectToAction(nameof(TwoFactorLoginHandler), new { email = user.Email });

                    }
                    else
                    {
                        return View("Error", new List<string>
                        {
                            "External login failed. Please try again"
                        });
                    }
                }
                else
                {
                    string email = externalLoginInfo.Principal?.FindFirstValue("email") ??
                        externalLoginInfo.Principal?.FindFirstValue(ClaimTypes.Email);
                    if (!string.IsNullOrEmpty(email))
                    {
                        user = await _userManager.FindByEmailAsync(email);
                        if (user != null)
                        {
                            await _userManager.AddLoginAsync(user, externalLoginInfo);
                            var signInResult = await _signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey, true);
                            if (signInResult.Succeeded)
                            {
                                return RedirectToAction("Index", "Home");
                            }
                            else
                            {
                                return View("Error", new List<string>
                                {
                                    "External login failed. Please try again"
                                });
                            }
                        }
                        else
                        {
                            string name = externalLoginInfo.Principal?.FindFirstValue("name") ??
                                externalLoginInfo.Principal?.FindFirstValue(ClaimTypes.Name) ??
                                email;
                            AppUser newUser = new AppUser
                            {
                                FullName = name,
                                Email = email,
                                EmailConfirmed = true,
                                LockoutEnabled = false,
                                IsAuthenticatorKeyEnabled = false,
                                UserName = email
                            };
                            var createUserResult = await _userManager.CreateAsync(newUser);
                            if (createUserResult.Succeeded)
                            {
                                await _userManager.AddLoginAsync(newUser, externalLoginInfo);
                                var signInResult = await _signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey, true);
                                if (signInResult.Succeeded)
                                {
                                    return RedirectToAction("Index", "Home");
                                }
                                else
                                {
                                    return View("Error", new List<string>
                                {
                                    "External login failed. Please try again"
                                });
                                }
                            }
                            else
                            {
                                return View("Error", createUserResult.Errors.Select(c => c.Description).ToList());
                            }
                        }
                    }
                    else
                    {
                        return View("Error", new List<string>
                        {
                            "External login failed. Email claim is empty"
                        });
                    }
                }
            }
            return View("Error", new List<string>
            {
                "External login info object is null. External login process is failed"
            });
        }

        private async Task<IActionResult> CommonLogin(AppUser user, string password)
        {
            var signInResult = await _signInManager.PasswordSignInAsync(user, password, false, true);
            if (signInResult.Succeeded)
            {
                return RedirectToAction("Index", "Home");
            }
            else if (signInResult.IsLockedOut)
            {
                await HttpContext.SignOutAsync();

                return RedirectToAction("Blocked");
            }
            return View("Error", new List<string>
            {
                "An error occured during login phase"
            });
        }
        public async Task<IActionResult> TwoFactorLoginHandler(string email)
        {
            var user = await _userManager.FindByNameAsync(email);
            IList<string> listProviders = await _userManager.GetValidTwoFactorProvidersAsync(user);
            if (listProviders.Contains(_userManager.Options.Tokens.AuthenticatorTokenProvider) &&
                    !user.IsAuthenticatorKeyEnabled)
            {
                listProviders.Remove(_userManager.Options.Tokens.AuthenticatorTokenProvider);
            }
            if (listProviders.Count == 1 && listProviders.FirstOrDefault().Equals("Email"))
            {

                return await TwoFactorLogin(user, "Email");

            }
            else if (listProviders.Count > 0)
            {
                return View(new TwoFactorLoginHandlerViewModel
                {
                    Email = email,
                    Providers = listProviders
                });
            }

            return View("Error", new List<string>
            {
                "No valid two factor token provider exists"
            });
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> TwoFactorLoginHandler(TwoFactorLoginHandlerViewModel model)
        {
            AppUser user = await _userManager.FindByEmailAsync(model.Email);
            return await TwoFactorLogin(user, model.Provider);
        }
        private async Task<IActionResult> TwoFactorLogin(AppUser user, string choosenProvider)
        {
            var tokenProvider = await _userManager.GetValidTwoFactorProvidersAsync(user);
            if (choosenProvider.Equals("Email"))
            {
                string token = await _userManager.GenerateTwoFactorTokenAsync(user, choosenProvider);
                //you can send the token to email here
                System.IO.File.WriteAllText("TwoFactorToken.txt", $"User Id: {user.Id}\r\nProvider: {choosenProvider}\r\nToken: {token}\r\n");

                return View(nameof(VerifyTokenTwoFactorToken), new TwoFactorTokenViewModel
                {
                    UserId = user.Id,
                    Provider = choosenProvider
                });
            }
            else
            {
                return View(nameof(VerifyTokenTwoFactorToken), new TwoFactorTokenViewModel
                {
                    UserId = user.Id,
                    Provider = choosenProvider
                });
            }
        }
        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyTokenTwoFactorToken(TwoFactorTokenViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(model.UserId);
                if (user != null)
                {
                    if (await _userManager.VerifyTwoFactorTokenAsync(user, model.Provider, model.Token))
                    {
                        await _signInManager.SignInAsync(user, true, IdentityConstants.ApplicationScheme);
                        return RedirectToAction("Index", "Home");
                    }
                }
                return View("Error", new List<string>
                {
                    "User not found"
                });
            }
            return View("Error", new List<string>
            {
                "Invalid payload data"
            });
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return RedirectToAction("Login");

        }

        public async Task<IActionResult> ConfirmEmail(string id = "", string token = "")
        {
            if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(token))
            {
                return View("Error", new List<string>
                {
                    "Invalid id or token for email confirmation"
                });
            }
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return View("Error", new List<string>
                {
                    "Invalid id, user not found"
                });
            }
            IdentityResult identityResult = await _userManager.ConfirmEmailAsync(user, token);
            if (identityResult.Succeeded)
            {
                return RedirectToAction(nameof(EmailConfirmed));
            }
            return View("Error", identityResult.Errors.Select(c => c.Description).ToList());
        }
        public IActionResult EmailConfirmed()
        {
            return View();
        }

        public IActionResult CheckYourEmail(CheckEmailEnum reason)
        {
            string message = string.Empty;

            switch (reason)
            {
                case CheckEmailEnum.Registration:
                    message = "Registration succeeded. Check your email inbox for account activation.";
                    break;
                case CheckEmailEnum.ForgetPassword:
                    message = "Check your email inbox to reset your password";
                    break;
            }
            return View((object)message);
        }

        [Authorize]
        public async Task<IActionResult> Settings()
        {
            try
            {

                var user = await _userManager.FindByNameAsync(User.Identity.Name);
                var twoFactorProviders = await _userManager.GetValidTwoFactorProvidersAsync(user);
                bool authenticatorEnabled = twoFactorProviders.Contains(
                        _userManager.Options.Tokens.AuthenticatorTokenProvider
                    ) && user.IsAuthenticatorKeyEnabled;
                return View(new ProfileSettingsViewModel
                {
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    AuthenticatorEnabled = authenticatorEnabled
                });
            }
            catch (Exception ex)
            {
                List<string> errors = new List<string>();
                Exception current = ex;
                while (current != null)
                {
                    errors.Add(current.Message);
                    current = current.InnerException;
                }
                return View("Error", errors);
            }
        }

        [Authorize, HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleMFA(ToggleMFAViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(User.Identity.Name);

                var updateResult = await _userManager.SetTwoFactorEnabledAsync(user, model.Active);

                if (updateResult.Succeeded)
                {
                    return RedirectToAction(nameof(Settings), "Auth");
                }
                return View("Error", updateResult.Errors.Select(c => c.Description).ToList());
            }
            return RedirectToAction(nameof(Settings), "Auth");

        }

        [Authorize]
        public async Task<JsonResult> RegisterAuthenticatorKey()
        {
            AppUser user = await _userManager.GetUserAsync(User);
            string authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(authenticatorKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }
            RegisterAuthenticatorKeyViewModel response = new RegisterAuthenticatorKeyViewModel
            {
                AuthenticatorKey = authenticatorKey
            };
            var validProviders = await _userManager.GetValidTwoFactorProvidersAsync(user);
            if (validProviders.Contains(_userManager.Options.Tokens.AuthenticatorTokenProvider))
            {
                user.IsAuthenticatorKeyEnabled = true;
                await _userManager.UpdateAsync(user);

                response.AlreadyActivated = true;

            }

            return Json(response);
        }
        [Authorize, HttpPost]
        public async Task<JsonResult> RegisterAuthenticatorKey(RegisterAuthenticatorKeyViewModel model)
        {
            if (string.IsNullOrEmpty(model.Token))
            {
                return Json(new { success = false, error = "Invalid token" });
            }
            if (string.IsNullOrEmpty(model.AuthenticatorKey))
            {
                return Json(new { success = false, error = "Invalid authenticator key" });
            }
            AppUser user = await _userManager.GetUserAsync(User);
            if (await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Token))
            {
                user.IsAuthenticatorKeyEnabled = true;
                await _userManager.UpdateAsync(user);
                return Json(new { success = true, error = string.Empty });
            }
            return Json(new { success = false, error = "Token was not verified successfully" });
        }

        [Authorize, HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> DeactivateAuthenticator()
        {
            AppUser user = await _userManager.GetUserAsync(User);
            user.IsAuthenticatorKeyEnabled = false;
            await _userManager.UpdateAsync(user);

            return RedirectToAction(nameof(Settings));
        }
        public IActionResult AccessDenied()
        {
            return View();
        }
        public IActionResult Blocked()
        {
            return View();
        }
    }
}