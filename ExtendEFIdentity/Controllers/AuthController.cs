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

        public IActionResult Login()
        {
            return View();
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
                            return await TwoFactorLogin(user);
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
        private async Task<IActionResult> TwoFactorLogin(AppUser user)
        {
            var tokenProvider = await _userManager.GetValidTwoFactorProvidersAsync(user);
            string provider = tokenProvider.FirstOrDefault(c => c.ToLower().Contains("email"));
            if (!string.IsNullOrEmpty(provider))
            {

                string token = await _userManager.GenerateTwoFactorTokenAsync(user, provider);
                //you can send the token to email here
                System.IO.File.WriteAllText("TwoFactorToken.txt", $"User Id: {user.Id}\r\nProvider: {provider}\r\nToken: {token}\r\n");

                return View(nameof(VerifyTokenTwoFactorToken), new TwoFactorTokenViewModel
                {
                    UserId = user.Id,
                    Provider = provider
                });

            }
            return View("Error", new List<string>
            {
                "No valid two factor token provider exists"
            });
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
                return View(new ProfileSettingsViewModel
                {
                    TwoFactorEnabled = user.TwoFactorEnabled
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
                user.TwoFactorEnabled = model.Active;
                var updateResult = await _userManager.UpdateAsync(user);
                if (updateResult.Succeeded)
                {
                    return RedirectToAction(nameof(Settings), "Auth");
                }
                return View("Error", updateResult.Errors.Select(c => c.Description).ToList());
            }
            return RedirectToAction(nameof(Settings), "Auth");

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