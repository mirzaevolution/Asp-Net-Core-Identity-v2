using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ExtendEFIdentity.Models;
using Microsoft.AspNetCore.Authorization;

namespace ExtendEFIdentity.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }
        public IActionResult Index()
        {
            _logger.LogInformation(1000, $">> Accessing page - {nameof(Index)}");
            return View();
        }
        [Authorize(Roles = "ADMIN")]
        public IActionResult Privacy()
        {
            _logger.LogInformation(1000, $">> Accessing page - {nameof(Privacy)}");
            return View();
        }

        [Authorize("ReaderPolicy")]
        public IActionResult Reader()
        {
            _logger.LogInformation(1000, $">> Accessing page - {nameof(Reader)}");
            return View();
        }
    }
}
