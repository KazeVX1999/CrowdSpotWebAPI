﻿//------------------------------------------------------------------------------
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
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    
    public partial class db_1919280_crowdspotdbEntities : DbContext
    {
        public db_1919280_crowdspotdbEntities()
            : base("name=db_1919280_crowdspotdbEntities")
        {
        }
    
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            throw new UnintentionalCodeFirstException();
        }
    
        public virtual DbSet<authenticateLoginTable> authenticateLoginTables { get; set; }
        public virtual DbSet<cameraMarksCoordinate> cameraMarksCoordinates { get; set; }
        public virtual DbSet<cameraStreamTable> cameraStreamTables { get; set; }
        public virtual DbSet<recordPeopleCountTable> recordPeopleCountTables { get; set; }
        public virtual DbSet<resetPasswordTable> resetPasswordTables { get; set; }
        public virtual DbSet<tempUserTable> tempUserTables { get; set; }
        public virtual DbSet<userCameraTable> userCameraTables { get; set; }
        public virtual DbSet<userLocationSurveillanceTable> userLocationSurveillanceTables { get; set; }
        public virtual DbSet<userTable> userTables { get; set; }
        public virtual DbSet<webStreamSignalTable> webStreamSignalTables { get; set; }
    }
}
