using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityNetCore.Models;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityNetCore.Controllers
{
    public class IdentityController : Controller
    {
        public async Task<IActionResult> Signup()
        {
           var model = new SignUpViewModel();
           return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignUpViewModel model)
        {
           return View(model);
        }
       
        public async Task<IActionResult> Signin()
        {
           return View();
        }

        public async Task<IActionResult> AccessDenied()
        {
           return View();
        }

    }
}