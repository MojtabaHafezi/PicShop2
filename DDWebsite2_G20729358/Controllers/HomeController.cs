using DDWebsite2_G20729358.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

   

namespace DDWebsite2_G20729358.Controllers
{
    [AllowAnonymous]
    public class HomeController : Controller
    {
        // caches for 5min
      
        public ActionResult Index()
        {

            return View();
        }
        [OutputCache(Duration = 300, VaryByParam = "none", Location = System.Web.UI.OutputCacheLocation.Server)]
        public ActionResult About()
        {
           
           ViewBag.Message = "Your application description page.";
           
            return View();
        }
        [OutputCache(Duration = 300, VaryByParam = "none", Location = System.Web.UI.OutputCacheLocation.Server)]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}