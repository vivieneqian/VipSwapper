using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using CloudSense.Models;
using System.Threading.Tasks;

namespace CloudSense.Controllers
{
    public class HomeController : Controller
    {
        private DataAccess db = new DataAccess();

        public async Task<ActionResult> Index()
        {
            ViewModel model = null;

            if (ClaimsPrincipal.Current.Identity.IsAuthenticated)
            {
                string userId = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value;
                model = new ViewModel();
                model.ConnectedSubscriptions = new List<Subscription>();
                var connectedSubscriptions = db.Subscriptions.Where<Subscription>(s => s.ConnectedBy == userId);
                foreach (var connectedSubscription in connectedSubscriptions)
                {
                    bool servicePrincipalHasReadAccessToSubscription = await AzureResourceManagerUtil.
                        DoesServicePrincipalHaveReadAccessToSubscription(connectedSubscription.Id, connectedSubscription.DirectoryId);
                    connectedSubscription.AzureAccessNeedsToBeRepaired = !servicePrincipalHasReadAccessToSubscription;

                    model.ConnectedSubscriptions.Add(connectedSubscription);
                }
            }

            return View(model);
        }
        public async Task ConnectSubscription(string subscriptionId)
        {
            string directoryId = await AzureResourceManagerUtil.GetDirectoryForSubscription(subscriptionId);

            if (!String.IsNullOrEmpty(directoryId))
            {
                if (!User.Identity.IsAuthenticated || !directoryId.Equals(ClaimsPrincipal.Current.FindFirst
                    ("http://schemas.microsoft.com/identity/claims/tenantid").Value))
                {
                    HttpContext.GetOwinContext().Environment.Add("Authority",
                        string.Format(ConfigurationManager.AppSettings["Authority"] + "OAuth2/Authorize", directoryId));

                    Dictionary<string, string> dict = new Dictionary<string, string>();
                    dict["prompt"] = "select_account";

                    HttpContext.GetOwinContext().Authentication.Challenge(
                        new AuthenticationProperties (dict) { RedirectUri = this.Url.Action("ConnectSubscription", "Home") + "?subscriptionId=" + subscriptionId },
                        OpenIdConnectAuthenticationDefaults.AuthenticationType);
                }
                else {
                    string objectIdOfCloudSenseServicePrincipalInDirectory = await
                        AzureADGraphAPIUtil.GetObjectIdOfServicePrincipalInDirectory(directoryId, ConfigurationManager.AppSettings["ClientID"]);

                    await AzureResourceManagerUtil.GrantRoleToServicePrincipalOnSubscription
                        (objectIdOfCloudSenseServicePrincipalInDirectory, subscriptionId, directoryId);

                    Subscription s = new Subscription()
                    {
                        Id = subscriptionId,
                        DirectoryId = directoryId,
                        ConnectedBy = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value,
                        ConnectedOn = DateTime.Now
                    };

                    if (db.Subscriptions.Find(s.Id) == null)
                    {
                        db.Subscriptions.Add(s);
                        db.SaveChanges();
                    }

                    Response.Redirect(this.Url.Action("Index", "Home"));
                }
            }

            return;
        }
        public async Task DisconnectSubscription(string subscriptionId)
        {
            string directoryId = await AzureResourceManagerUtil.GetDirectoryForSubscription(subscriptionId);

            string objectIdOfCloudSenseServicePrincipalInDirectory = await
                AzureADGraphAPIUtil.GetObjectIdOfServicePrincipalInDirectory(directoryId, ConfigurationManager.AppSettings["ClientID"]);

            await AzureResourceManagerUtil.RevokeRoleFromServicePrincipalOnSubscription
                (objectIdOfCloudSenseServicePrincipalInDirectory, subscriptionId, directoryId);

            Subscription s = db.Subscriptions.Find(subscriptionId);
            if (s != null)
            {
                db.Subscriptions.Remove(s);
                db.SaveChanges();
            }

            Response.Redirect(this.Url.Action("Index", "Home"));
        }
        public async Task RepairSubscriptionConnection(string subscriptionId)
        {
            string directoryId = await AzureResourceManagerUtil.GetDirectoryForSubscription(subscriptionId);

            string objectIdOfCloudSenseServicePrincipalInDirectory = await
                AzureADGraphAPIUtil.GetObjectIdOfServicePrincipalInDirectory(directoryId, ConfigurationManager.AppSettings["ClientID"]);

            await AzureResourceManagerUtil.RevokeRoleFromServicePrincipalOnSubscription
                (objectIdOfCloudSenseServicePrincipalInDirectory, subscriptionId, directoryId);
            await AzureResourceManagerUtil.GrantRoleToServicePrincipalOnSubscription
                (objectIdOfCloudSenseServicePrincipalInDirectory, subscriptionId, directoryId);

            Response.Redirect(this.Url.Action("Index", "Home"));
        }
    }
}