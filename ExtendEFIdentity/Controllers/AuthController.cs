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
                        var signInResult = await _signInManager.PasswordSignInAsync(appUser, model.Password, false, false);
                        if (signInResult.Succeeded)
                        {
                            return RedirectToAction("Index", "Home");
                        }
                        else
                        {

                            ModelState.AddModelError("", "User registration was successful, but error occured during login. Try login again using Login page");
                            return View(model);
                        }
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