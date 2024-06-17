using Microsoft.AspNetCore.Mvc;

namespace TheIdentityServer.Controllers
{
    public class BaseWebController<T> : Controller
    {
        ILogger<T>? logger;

        protected ILogger<T>? Logger => logger ??= HttpContext.RequestServices.GetService<ILogger<T>>();
       
    }
}
