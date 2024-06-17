using Microsoft.AspNetCore.Mvc;

namespace SSO.TheOpenIddict;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}