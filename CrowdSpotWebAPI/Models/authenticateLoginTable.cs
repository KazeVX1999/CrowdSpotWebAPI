//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace CrowdSpotWebAPI.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class authenticateLoginTable
    {
        public int authenticationID { get; set; }
        public string authenticationCode { get; set; }
        public int userID { get; set; }
        public System.DateTime dateAuthenticated { get; set; }
    
        public virtual userTable userTable { get; set; }
    }
}
