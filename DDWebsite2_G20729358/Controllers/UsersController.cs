using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using DDWebsite2_G20729358.Models;
using System.Web.Security;
using System.Security.Claims;
using System.Security.Permissions;
using DDWebsite2_G20729358.Security;
using BCrypt.Net;

namespace DDWebsite2_G20729358.Controllers
{
    public class UsersController : Controller
    {
        private Database1Entities1 db = new Database1Entities1();

        [Authorize(Roles = "ADMIN")]
        // GET: Users
        public ActionResult Index()
        {
            return View(db.Users.ToList());
        }

        // GET: Users/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // GET: Users/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        // POST: Users/Register
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]

        public ActionResult Register([Bind(Include = "Id,Username,Firstname,Lastname,Email,Password,ConfirmPassword,UserRole")] User user)
        {
            if (String.IsNullOrEmpty(user.UserRole))
                user.UserRole = UserRole.USER.ToString();
            if (ModelState.IsValid)
            {
                //Using BCrypt Password hashing + salting
                string hashed = BCrypt.Net.BCrypt.HashPassword(user.Password);
                 user.Password = user.ConfirmPassword = hashed;
             
                db.Users.Add(user);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            return View(user);
        }

        // GET: Users/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // POST: Users/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "Id,Username,Firstname,Lastname,Email,Password,ConfirmPassword,UserRole")] User user)
        {
            var RoleList = new List<string>();
            // add the roles as a list of string
            RoleList.AddRange(Enum.GetNames(typeof(UserRole)).ToList());  
            ViewBag.listOfRoles = new SelectList(RoleList);

            if (ModelState.IsValid)
            {
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            return View(user);
        }

        // GET: Users/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // POST: Users/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            User user = db.Users.Find(id);
            db.Users.Remove(user);
            db.SaveChanges();
            return RedirectToAction("Index");
        }
        [Authorize]
        public ActionResult Logout()
        {
            Session.Clear();
            var ctx = Request.GetOwinContext();
            var authManager = ctx.Authentication;

            authManager.SignOut("ApplicationCookie");
            // FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Games");
        }
        [AllowAnonymous]
        public ActionResult Login()
        {
            return View();
        }
        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login([Bind(Include = "Id,Username,Firstname,Lastname,Email,Password,ConfirmPassword,UserRole")] User user)
        {
            var compareUser = IsValid(user.Username, user.Password);
            if(compareUser != null)
            {
                //FormsAuthentication.SetAuthCookie(compareUser.Username, true);
                Session["UserID"] = compareUser.Id.ToString();
                Session["Username"] = compareUser.Username.ToString();
                Session["UserRole"] = compareUser.UserRole.ToString();

                var identity = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.NameIdentifier, compareUser.Username.ToString()),
                    new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider", "ASP.NET Identity", "http://www.w3.org/2001/XMLSchema#string"),
                    new Claim(ClaimTypes.Name, compareUser.Username.ToString()),
                    new Claim(ClaimTypes.Role, compareUser.UserRole.ToString()),
                },"ApplicationCookie");

                var ctx = Request.GetOwinContext();
                var authManager = ctx.Authentication;
                authManager.SignIn(identity);

                return RedirectToAction("Index", "Games");
            } 
            else
            {
                ModelState.AddModelError("", "Username or Password is not correct.");

            }

            return View();
        }

  
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        public User IsValid(String username, String password)
        {
            
            var compareUser = db.Users.Where(u => u.Username == username).FirstOrDefault();
           bool matches = BCrypt.Net.BCrypt.Verify(password, compareUser.Password);
           if (matches)
            return compareUser;
            else
            return null;
        }
    }
}
