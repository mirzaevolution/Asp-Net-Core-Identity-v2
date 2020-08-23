using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using BasicCustomIdentity.Entities;
using BasicCustomIdentity.Models;
using Microsoft.AspNetCore.Authorization;

namespace BasicCustomIdentity.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<BasicUser> _userManager;
        private readonly SignInManager<BasicUser> _signInManager;
        public AccountController(UserManager<BasicUser> userManager, SignInManager<BasicUser> signInManager)
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
        public async Task<IActionResult> Register(RegisterUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                BasicUser basicUser = new BasicUser
                {
                    FullName = model.FullName,
                    UserName = model.UserName
                };
                var result = await _userManager.CreateAsync(basicUser, model.Password);
                if (result.Succeeded)
                {
                    var signInResult = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, false, false);
                    if (signInResult.Succeeded)
                    {
                        return RedirectToAction("Index", "Home");
                    }
                    return View("Error", new List<string>
                    {
                        "Unknown issue occured during login process"
                    });
                }
                return View("Error", result.Errors.Select(c => c.Description).ToList());
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
                var user = await _userManager.FindByNameAsync(model.UserName);
                if (user != null)
                {
                    var signInResult = await _signInManager.PasswordSignInAsync(user, model.Password, false, false);
                    if (signInResult.Succeeded)
                    {
                        return RedirectToAction("Index", "Home");
                    }
                    return View("Error", new List<string>
                    {
                        "Login failed"
                    });
                }
                ModelState.AddModelError("", "User not found");
            }
            return View(model);
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return RedirectToAction("Index", "Home");
        }
    }
}
