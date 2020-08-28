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

                    var signInResult = await _signInManager.PasswordSignInAsync(user, model.Password, false, true);
                    if (signInResult.Succeeded)
                    {
                        return RedirectToAction("Index", "Home");
                    }
                    else if (signInResult.IsLockedOut)
                    {
                        await HttpContext.SignOutAsync();

                        return RedirectToAction("Blocked");
                    }
                }
                ModelState.AddModelError("", "Invalid username or password");
            }
            return View(model);
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