// User controller
// User models & login models
// User views folder & views
//routes, home, register, logout


using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using LoginAndRegistrationCore.Models;
//added:
using Microsoft.AspNetCore.Identity;
using System.Reflection.Metadata.Ecma335;

//Added for session check
using Microsoft.AspNetCore.Mvc.Filters;

namespace LoginAndRegistrationCore.Controllers;

public class UserController : Controller
{
    private readonly ILogger<UserController> _logger;
    
    private MyContext db;


    public UserController(ILogger<UserController> logger, MyContext context)
    {
        _logger = logger;
        db = context;
    }
//   view Index Page ============================================

    [HttpGet("")]
    public IActionResult Index()
    {
    return View("Index");
    // RedirectToAction("Index", "User")
    }
//   view Success Page ============================================
    [SessionCheck]
    [HttpGet("Success")]
    public IActionResult Success()
        {
    return View("Success");  
    // return RedirectToAction("Success", "User");
        }
    

//  method ============================================
    [HttpPost("/register")]
    public IActionResult Register(User newUser)
    {
        if(!ModelState.IsValid)
        {
            return View("Index");
        }
        // add pw hasher:
        PasswordHasher<User> hashBrowns = new PasswordHasher<User>();
        newUser.Password = hashBrowns.HashPassword(newUser, newUser.Password);

        db.Users.Add(newUser);
        db.SaveChanges();
        HttpContext.Session.SetInt32("UUID", newUser.UserId);


        return RedirectToAction("Success", "User");
    }
//  Login method ================================================
    [HttpPost("/login")]
    public IActionResult Login(LoginUser userSubmission)
    {
        if(!ModelState.IsValid)
        {
            return View("Index");
        }
        //EMAIL CHECK HERE
        User? userInDb = db.Users.FirstOrDefault(e => e.Email == userSubmission.LoginEmail);        
        // If no user exists with the provided email        
        if(userInDb == null)        
        {            
            ModelState.AddModelError("LoginEmail", "Invalid Email/Password");
            return View("Index");
        }
        //PASSWORD CHECK
        PasswordHasher<LoginUser> hashBrowns = new PasswordHasher<LoginUser>();                    
        var result = hashBrowns.VerifyHashedPassword(userSubmission, userInDb.Password, userSubmission.LoginPassword);
        if(result == 0)
        {
            ModelState.AddModelError("LoginPassword", "Invalid Password/Email");
            return View("Index");
        }

        //Handle success
        HttpContext.Session.SetInt32("UUID", userInDb.UserId);

        return RedirectToAction("Success", "User");
    }


// Logout Method ================================================
[HttpPost("logout")]
public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index");
    }



// Privacy Method ================================================



    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}

//Added - SESSION CHECK ===========================================
// Name this anything you want with the word "Attribute" at the end -- adding filter for session at top*
public class SessionCheckAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        // Find the session, but remember it may be null so we need int?
        int? userId = context.HttpContext.Session.GetInt32("UUID");
        // Check to see if we got back null
        if(userId == null)
        {
            // Redirect to the Index page if there was nothing in session
            // "Home" here is referring to "HomeController", you can use any controller that is appropriate here
            context.Result = new RedirectToActionResult("Index", "User", null);
        }
    }
}