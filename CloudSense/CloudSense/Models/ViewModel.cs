using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CloudSense.Models
{
    public class ViewModel
    {
        public ICollection<Subscription> ConnectedSubscriptions { get; set; }
    }
}