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
    
    public partial class userLocationSurveillanceTable
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public userLocationSurveillanceTable()
        {
            this.recordPeopleCountTables = new HashSet<recordPeopleCountTable>();
            this.userCameraTables = new HashSet<userCameraTable>();
        }
    
        public int locationID { get; set; }
        public int userID { get; set; }
        public string locationName { get; set; }
        public string locationDescription { get; set; }
        public int CurrentPeopleCount { get; set; }
    
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<recordPeopleCountTable> recordPeopleCountTables { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<userCameraTable> userCameraTables { get; set; }
        public virtual userTable userTable { get; set; }
    }
}
