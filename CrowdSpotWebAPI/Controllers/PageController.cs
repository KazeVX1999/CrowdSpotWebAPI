using System;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Linq;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Web.Script.Serialization;
using CrowdSpotWebAPI.Models;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using static Org.BouncyCastle.Math.EC.ECCurve;

namespace CrowdSpotWebAPI.Controllers
{
    [RoutePrefix("API")]
    public class PageController : ApiController
    {
        public db_1919280_crowdspotdbEntities theEntity = new db_1919280_crowdspotdbEntities();

        [HttpGet]
        [Route("LogIn")]
        public IHttpActionResult LogIn(string inputUserEmail, string inputUserPassword)
        {
            // Find user 
            userTable findingUser = theEntity.userTables.FirstOrDefault(theUser => theUser.userEmail == inputUserEmail);
            if (findingUser == null)
            {
                // User Fail Login due to Incorrect login detail.
                return Content(HttpStatusCode.NotFound, "- User Account Email Incorrect -");
            }

            if (!VerifyHashedPassword(findingUser.userPassword, inputUserPassword))
            {
                return Content(HttpStatusCode.NotFound, "- User Account Password Incorrect -");
            }

            // Find and Remove Old Authentication Record if passed 7days
            try
            {
                authenticateLoginTable removeOldAuthentication = theEntity.authenticateLoginTables.FirstOrDefault(theUser => theUser.userID == findingUser.userID);
                DateTime now = DateTime.UtcNow;
                if (removeOldAuthentication != null)
                {
                    System.TimeSpan timeDifference = now.Subtract(removeOldAuthentication.dateAuthenticated);

                    if (timeDifference.TotalHours > 168)
                    {
                        theEntity.authenticateLoginTables.Remove(removeOldAuthentication);
                        theEntity.SaveChanges();
                    }
                    
                }
            } catch
            {
                return Content(HttpStatusCode.NotFound, "- User Authentication Failed -");
            }


            try { 
                // Create new Authentication
                string validationCode = validationCodeGenerator(200);
                authenticateLoginTable newAuthentication = new authenticateLoginTable();
                newAuthentication.userID = findingUser.userID;
                newAuthentication.authenticationCode = validationCode;
                newAuthentication.dateAuthenticated = DateTime.UtcNow;
                theEntity.authenticateLoginTables.Add(newAuthentication);
                theEntity.SaveChanges();
                return Ok(validationCode);
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- User Authentication Failed -");
            }            
        }

        [HttpGet]
        [Route("AutoLogIn")]
        // Auto LogIn for 3 days
        public IHttpActionResult autoLogIn(string storedAuthenticatedCode)
        {
            try
            {
                // Find user with code
                authenticateLoginTable findMatch = theEntity.authenticateLoginTables.FirstOrDefault(theMatch => theMatch.authenticationCode == storedAuthenticatedCode);
                if (findMatch != null)
                {
                    // Check if the code still valid for 7days
                    DateTime now = DateTime.UtcNow;
                    System.TimeSpan timeDifference = now.Subtract(findMatch.dateAuthenticated);
                    if (timeDifference.TotalHours < 168)
                    {
                        // Return User when valid
                        return Ok(theEntity.userTables.Find(findMatch.userID));

                    }
                    else
                    {
                        return Content(HttpStatusCode.NotFound, "User Authentication Failed - Code Expired.");

                    }
                }
                else
                {
                    return Content(HttpStatusCode.NotFound, "User Authentication Failed - Code Incorrect.");
                }
            } catch (Exception error)
            {
                return Content(HttpStatusCode.NotFound, "Error: " + error + ".");
            }
            
        }


        [HttpGet, HttpPost, HttpDelete]
        [Route("SignUpProcess1")]
        // 3rd PROCESS ADD INTO TEMP USER TABLE INSTEAD of ORIGINAL USER TABLE.
        public IHttpActionResult registeringTempUser(string inputUserEmail, string inputUserPassword)
        {            
            try
            {
                // Check if Email are free to register.
                userTable check = theEntity.userTables.FirstOrDefault(theUser => theUser.userEmail == inputUserEmail);
                if (check != null)
                {
                    // If not null / does exists, then error.
                    return Content(HttpStatusCode.NotFound, "- User Email Registered Already -");
                }

                // Remove incomplete old registration if found
                tempUserTable checkTempUser = theEntity.tempUserTables.FirstOrDefault(theUser => theUser.userEmail == inputUserEmail);
                if (checkTempUser != null)
                {
                    theEntity.tempUserTables.Remove(checkTempUser);
                    theEntity.SaveChanges();
                }

                // Proceed to move user details to tempUserTable where user will need a verification code to validate this account then will be moved to real user table.
                string validationCodeGenerated = validationCodeGenerator(6);
                
                try
                {
                    // After added temporary, Send email to user along with the validation key.
                    MimeMessage theMessage = new MimeMessage();

                    MailMessage mail = new MailMessage();

                    mail.From = new MailAddress("crowdspotauto@gmail.com");
                    mail.To.Add(inputUserEmail);
                    mail.Subject = "Validating Registeration";
                    mail.Body = "<h3>This is an automated message please don't reply to this email address.</h3><h3>Thank you for choosing CrowdSpot. To finish your Sign Up, please enter the code from below to our page.</h3><h1 style=\"text-align: center\">" + validationCodeGenerated + "</h1><h3>If you wish to ask for help or have any enquiry, please do message us at: CrowdSpotWHW@gmail.com</h3>"; 
                    mail.IsBodyHtml = true;

                    try
                    {
                        using (System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient("smtp.gmail.com", 587))
                        {
                            smtp.UseDefaultCredentials = true;
                            smtp.Credentials = new NetworkCredential("crowdspotauto@gmail.com", "wonrhrbslkfabbcc");
                            smtp.EnableSsl = true;
                            smtp.Send(mail);
                            smtp.Dispose();
                        }
                    }
                    catch
                    {
                        return Content(HttpStatusCode.NotFound, "- SMTP Failed -");
                    }


                } catch (Exception)
                {
                    return Content(HttpStatusCode.NotFound, "Mail sending Failed.");
                }

                // After user got the mail, system will add the user to tempUserTable.
                tempUserTable newTempUser = new tempUserTable();
                newTempUser.userEmail = inputUserEmail;
                newTempUser.userPassword = HashPassword(inputUserPassword);
                newTempUser.validationCode = HashPassword(validationCodeGenerated);
                newTempUser.submittedTime = DateTime.UtcNow;
                theEntity.tempUserTables.Add(newTempUser);
                theEntity.SaveChanges();

                // Sign Up Process 3 succeeded.
                return Ok("- Sign Up Process 1 - Succeed -");
            }
            catch (Exception)
            {
                // Error Occurred.
                return Content(HttpStatusCode.NotFound, "- Sign Up Process 1 - Error Occurred -");
            }
            
        }
        [HttpGet, HttpPut]
        [Route("SignUpResendCode")]
        public IHttpActionResult resendCode(string inputUserEmail)
        {
            try
            {
                try
                {
                    tempUserTable checkUser = theEntity.tempUserTables.FirstOrDefault(user => user.userEmail == inputUserEmail);
                    if (checkUser == null)
                    {
                        return Content(HttpStatusCode.NotFound, "- Email Not Found -");
                    }
                }
                catch
                {
                    return Content(HttpStatusCode.NotFound, "- Email Check Error -");

                }

                string validationCodeGenerated = validationCodeGenerator(6);

                try
                {

                    MailMessage mail = new MailMessage();

                    mail.From = new MailAddress("crowdspotauto@gmail.com");
                    mail.To.Add(inputUserEmail);
                    mail.Subject = "Validating Registeration";
                    mail.Body = "<h3>This is an automated message please don't reply to this email address.</h3><h3>Thank you for choosing CrowdSpot. To finish your Sign Up, please enter the code from below to our page.</h3><h1 style=\"text-align: center\">" + validationCodeGenerated + "</h1><h3>If you wish to ask for help or have any enquiry, please do message us at: CrowdSpotWHW@gmail.com</h3>";
                    mail.IsBodyHtml = true;

                    try
                    {
                        using (System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient("smtp.gmail.com", 587))
                        {
                            smtp.UseDefaultCredentials = true;
                            smtp.Credentials = new NetworkCredential("crowdspotauto@gmail.com", "wonrhrbslkfabbcc");
                            smtp.EnableSsl = true;
                            smtp.Send(mail);
                            smtp.Dispose();
                        }
                    }
                    catch
                    {
                        return Content(HttpStatusCode.NotFound, "- SMTP Failed -");
                    }


                }
                catch (Exception)
                {
                    return Content(HttpStatusCode.NotFound, "Mail sending Failed.");
                }

                // Update user's sign up code.
                tempUserTable theTempUser = theEntity.tempUserTables.FirstOrDefault(user => user.userEmail == inputUserEmail);
                theTempUser.validationCode = HashPassword(validationCodeGenerated);
                theEntity.SaveChanges();

                // Sign Up Process 3 succeeded.
                return Ok("- Code Resend Succeed -");
            }
            catch (Exception)
            {
                // Error Occurred.
                return Content(HttpStatusCode.NotFound, "- Code Resend Failed -");
            }

        }

        [HttpGet, HttpPost, HttpDelete]
        [Route("SignUpProcess2")]
        public IHttpActionResult registeringUser(string inputUserEmail, string inputUserValidationCode)
        {
            try
            {
                tempUserTable searchTempUser = theEntity.tempUserTables.FirstOrDefault(theUser => theUser.userEmail == inputUserEmail);
                if (searchTempUser == null)
                {
                    return Content(HttpStatusCode.NotFound, "- User Not Found -");
                }

                if (!VerifyHashedPassword(searchTempUser.validationCode, inputUserValidationCode))
                {
                    return Content(HttpStatusCode.NotFound, "- Incorrect Validation Code -");
                }

                // Validation Code only valid within 1 hour.
                DateTime now = DateTime.UtcNow;
                System.TimeSpan timeDifference = now.Subtract(searchTempUser.submittedTime);
                if (timeDifference.TotalHours > 1)
                {
                    return Content(HttpStatusCode.NotFound, "- Validation Code Expired -");
                }


                // If Found, Add user to REAL User Table.
                try
                {
                    userTable newUser = new userTable();
                    newUser.userEmail = searchTempUser.userEmail;
                    newUser.userPassword = searchTempUser.userPassword;
                    theEntity.userTables.Add(newUser);
                    theEntity.SaveChanges();      

                    // Remove old registration
                    tempUserTable checkTempUser = theEntity.tempUserTables.FirstOrDefault(theUser => theUser.userEmail == inputUserEmail);
                    if (checkTempUser != null)
                    {
                        theEntity.tempUserTables.Remove(checkTempUser);
                        theEntity.SaveChanges();
                    }

                    return Ok("- Account Validated and Successfully Registered -");

                }
                catch (Exception)
                {
                    return Content(HttpStatusCode.NotFound, "- User Adding Failed -");
                }
            }
            catch (Exception)
            {
                return Content(HttpStatusCode.NotFound, "- Sign Up Process 2 - Error Occurred -");
            }

        }



        [HttpGet, HttpPost, HttpDelete]
        [Route("ResetProcess1")]
        public IHttpActionResult checkingUser(string inputUserEmail)
        {
            try
            {
                userTable checkUser = theEntity.userTables.FirstOrDefault(theUser => theUser.userEmail == inputUserEmail);
                if (checkUser == null)
                {
                    return Content(HttpStatusCode.NotFound, "- User Not Found -");
                }

                string validationCodeGenerated = validationCodeGenerator(8);

                try
                {
                    // Send email to user along with the validation key.
                    MailMessage mail = new MailMessage();

                    mail.From = new MailAddress("crowdspotauto@gmail.com");
                    mail.To.Add(inputUserEmail);
                    mail.Subject = "Resetting Password";
                    mail.Body = "<h3>This is an automated message please don' reply to this email address.</h3><h3>Dear User, you have requested for resetting your account's password. Here is your code for validation to ensure that this is you.</h3><h1 style=\"text-align: center\">" + validationCodeGenerated + "</h1><h3>If you wish to ask for help or have any enquiry, please do message us at: CrowdSpotWHW@gmail.com</h3>";
                    mail.IsBodyHtml = true;

                    try
                    {
                        using (System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient("smtp.gmail.com", 587))
                        {
                            smtp.UseDefaultCredentials = true;
                            smtp.Credentials = new NetworkCredential("crowdspotauto@gmail.com", "wonrhrbslkfabbcc");
                            smtp.EnableSsl = true;
                            smtp.Send(mail);
                            smtp.Dispose();
                        }
                    }
                    catch
                    {
                        return Content(HttpStatusCode.NotFound, "- SMTP Failed -");
                    }

                    // Remove if exist an old check
                    resetPasswordTable checkOldReset = theEntity.resetPasswordTables.FirstOrDefault(check => check.userID == checkUser.userID);
                    if (checkOldReset != null)
                    {
                        theEntity.resetPasswordTables.Remove(checkOldReset);
                        theEntity.SaveChanges();
                    }

                    resetPasswordTable newReset = new resetPasswordTable();
                    newReset.userID = checkUser.userID;
                    newReset.resetCode = HashPassword(validationCodeGenerated);
                    newReset.dateTimeRequested = DateTime.UtcNow;
                    theEntity.resetPasswordTables.Add(newReset);
                    theEntity.SaveChanges();
                    return Ok("- Code Sent to your Email -");

                }
                catch (Exception)
                {
                    return Content(HttpStatusCode.NotFound, "- Mail sending Failed -");
                }



            }
            catch (Exception)
            {
                return Content(HttpStatusCode.NotFound, "- Reset Process 1 - Error Occurred -");
            }

        }


        [HttpGet]
        [Route("ResetProcess2")]
        public IHttpActionResult checkingCode(string inputUserEmail, string inputResetCode)
        {
            try
            {
                userTable user = theEntity.userTables.FirstOrDefault(theUser => theUser.userEmail == inputUserEmail);
                if (user == null)
                {
                    return Content(HttpStatusCode.NotFound, "- User not Found -");
                }

                resetPasswordTable userReset = theEntity.resetPasswordTables.FirstOrDefault(reset => reset.userID == user.userID);
                if (user == null)
                {
                    return Content(HttpStatusCode.NotFound, "- User not Found -");
                }

                if (!VerifyHashedPassword(userReset.resetCode, inputResetCode))
                {
                    return Content(HttpStatusCode.NotFound, "- Validation Code Incorrect -");
                }

                // Validation Code only valid within 1 hour.
                DateTime now = DateTime.UtcNow;
                System.TimeSpan timeDifference = now.Subtract(userReset.dateTimeRequested);
                if (timeDifference.TotalHours > 1)
                {
                    return Content(HttpStatusCode.NotFound, "- Validation Code Expired -");
                }

                return Ok("Code Validated");

            } catch (Exception)
            {
                return Content(HttpStatusCode.NotFound, "- Reset Process 2 - Error Occurred -");
            }
        }

        [HttpGet, HttpPut]
        [Route("ResetProcess3")]
        public IHttpActionResult resetCode(string inputUserEmail, string inputNewPassword)
        {
            try
            {
                userTable user = theEntity.userTables.FirstOrDefault(theUser => theUser.userEmail == inputUserEmail);
                if (user == null)
                {
                    return Content(HttpStatusCode.NotFound, "- User not Found -");
                }

                user.userPassword = HashPassword(inputNewPassword);
                theEntity.SaveChanges();

                // After added temporary, Send email to user along with the validation key.
                MailMessage mail = new MailMessage();

                mail.From = new MailAddress("crowdspotauto@gmail.com");
                mail.To.Add(inputUserEmail);
                mail.Subject = "Successfully Reset Password";
                mail.Body = "<h3>This is an automated message please don't reply to this email address.</h3><h3>Dear User, you have successfully resetting your account's password.</h3><h3>If you wish to ask for help or have any enquiry, please do message us at: CrowdSpotWHW@gmail.com</h3>";
                mail.IsBodyHtml = true;

                try
                {
                    using (System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient("smtp.gmail.com", 587))
                    {
                        smtp.UseDefaultCredentials = true;
                        smtp.Credentials = new NetworkCredential("crowdspotauto@gmail.com", "wonrhrbslkfabbcc");
                        smtp.EnableSsl = true;
                        smtp.Send(mail);
                        smtp.Dispose();
                    }
                }
                catch
                {
                    return Content(HttpStatusCode.NotFound, "- SMTP Failed -");
                }

                return Ok("- Reset Password Succeed -");
            }
            catch (Exception)
            {
                return Content(HttpStatusCode.NotFound, "- Reset Process 3 - Error Occurred -");
            }
        }

        [HttpGet, HttpPost]
        [Route("UserEnquiry")]
        public IHttpActionResult userEnquiry(string inputUserEmail, string subjectMessage, string textMessage)
        {
            try
            {
               
                // Code adapted from msu-nasir and eocron (2021).
                MailMessage mail = new MailMessage();
                mail.From = new MailAddress(inputUserEmail);
                mail.To.Add("crowdspotwhw@gmail.com");
                mail.Subject = "From: " + inputUserEmail;
                mail.Body = "<h3>Subject: " + subjectMessage + "</h3><h4>Description: " + textMessage + "</h4>";
                mail.IsBodyHtml = true;

                try
                {
                    using (System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient("smtp.gmail.com", 587))
                    {
                        smtp.UseDefaultCredentials = true;
                        smtp.Credentials = new NetworkCredential("crowdspotauto@gmail.com", "wonrhrbslkfabbcc");
                        smtp.EnableSsl = true;
                        smtp.Send(mail);
                        smtp.Dispose();
                    }
                }
                    catch
                {
                    return Content(HttpStatusCode.NotFound, "- SMTP Failed -");
                }

                // End of code adapted.




                return Ok("- Message Successfully Submitted -");
            }
            catch (Exception)
             {
                 return Content(HttpStatusCode.NotFound, "- Message Submission Failed -");
             }

         }

        [HttpGet, HttpPut]
        [Route("ChangePassword")]
        public IHttpActionResult changePassword(int userID, string currentPassword, string newPassword)
        {
            userTable theUser = theEntity.userTables.Find(userID);
            if (theUser == null)
            {
                return Content(HttpStatusCode.NotFound, "- User Not Found -");
            }

            if (!VerifyHashedPassword(theUser.userPassword, currentPassword))
            {
                return Content(HttpStatusCode.NotFound, "- User Incorrect Current Password -");
            }

            try
            {
                theUser.userPassword = HashPassword(newPassword);
                theEntity.SaveChanges();
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Change Password Failed -");
            }


            try
            {
                MailMessage mail = new MailMessage();

                mail.From = new MailAddress("crowdspotauto@gmail.com");
                mail.To.Add(theUser.userEmail);
                mail.Subject = "Account Password Changed";
                mail.Body = "<h3>This is an automated message please don't reply to this email address.</h3><h3>This mail is to tell you that you have been succesfully changed your account's password. If it wasn't you who changed the password, please do contact us at: CrowdSpotWHW@gmail.com</h3>";
                mail.IsBodyHtml = true;

                try
                {
                    using (System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient("smtp.gmail.com", 587))
                    {
                        smtp.UseDefaultCredentials = true;
                        smtp.Credentials = new NetworkCredential("crowdspotauto@gmail.com", "wonrhrbslkfabbcc");
                        smtp.EnableSsl = true;
                        smtp.Send(mail);
                        smtp.Dispose();
                    }
                }
                catch
                {
                    return Content(HttpStatusCode.NotFound, "- SMTP Failed -");
                }
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Mail sent Failed -");
            }

            return Ok("- Password Successfully changed -");

        }

        [HttpGet, HttpPost]
        [Route("AddNewLocation")]
        public IHttpActionResult AddNewLocation(int userID, string locationName, string locationDescription)
        {
            try
            {
                userLocationSurveillanceTable newLocation = new userLocationSurveillanceTable();
                newLocation.userID = userID;
                newLocation.locationName = locationName;
                newLocation.locationDescription = locationDescription;
                newLocation.CurrentPeopleCount = 0;
                theEntity.userLocationSurveillanceTables.Add(newLocation);
                theEntity.SaveChanges();
                return Ok("- " + locationName + " Successfully Added -");
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Location Add Failed -");
            }

        }

        [HttpGet]
        [Route("RefreshLocations")]
        public IHttpActionResult RefreshLocations(int userID, int sort)
        {
            try
            {
                // Code Adapted from w3Schools.com, n.d; GeeksForGeeks, 2021; M.Eliasson, 2017.
                
                var SQLScript = "";
                switch (sort)
                {
                    case (1):
                        SQLScript = "select * from userLocationSurveillanceTable where userID='" + userID + "' ORDER BY locationName ASC";
                        break;
                    case (2):
                        SQLScript = "select * from userLocationSurveillanceTable where userID='" + userID + "' ORDER BY locationName DESC";
                        break;
                    case (3):
                        SQLScript = "select * from userLocationSurveillanceTable where userID='" + userID + "' ORDER BY CurrentPeopleCount ASC";
                        break;
                    case (4):
                        SQLScript = "select * from userLocationSurveillanceTable where userID='" + userID + "' ORDER BY CurrentPeopleCount DESC";
                        break;
                    default:
                        SQLScript = "select * from userLocationSurveillanceTable where userID='" + userID + "' ORDER BY locationName ASC";
                        break;
                }
                // End of Code Adapted

                var surveillances = theEntity.Database.SqlQuery<userLocationSurveillanceTable>(SQLScript).ToList();


                // 1st = surveillances[], 2nd = Total of Cameras Online of that Location, 3rd = Total of Cameras Added of that Locations, 4 = People Counts
                ArrayList output = new ArrayList();
                for (int i = 0; i < surveillances.Count; i++)
                {
                    var totalCamerasOnline = theEntity.Database.SqlQuery<int>("select COUNT(*) from userCameraTable where locationID = '" + surveillances[i].locationID + "' AND operationStatus = '1' AND operatingStatus = '1';");
                    var totalCameras = theEntity.Database.SqlQuery<int>("select COUNT(*) from userCameraTable where locationID='" + surveillances[i].locationID + "'");

                    ArrayList addingList;

                    // Code Adapted from TutorialsTeacher.com, n.d.
                    addingList = new ArrayList { surveillances[i], totalCamerasOnline, totalCameras, surveillances[i].CurrentPeopleCount };
                    

                    output.Add(addingList);
                    // End of Code Adapted
                }

                return Ok(output);
            }
            catch (Exception e)
            {
                return Content(HttpStatusCode.NotFound, "- API Error " + e + " -");
            }
        }

        [HttpGet]
        [Route("GetSurveillance")]
        public IHttpActionResult GetSurveillance(int userID, int locationID)
        {
            try
            {
                userLocationSurveillanceTable theLocation = theEntity.userLocationSurveillanceTables.FirstOrDefault(location => location.userID == userID && location.locationID == locationID);
                if (theLocation == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Location Not Found -");
                } else
                {
                    var totalCamerasOnline = theEntity.Database.SqlQuery<int>("select COUNT(*) from userCameraTable where locationID = '" + theLocation.locationID + "' AND operationStatus = '1' AND operatingStatus = '1';");
                    var totalCameras = theEntity.Database.SqlQuery<int>("select COUNT(*) from userCameraTable where locationID='" + theLocation.locationID + "'");

                    ArrayList output;


                    // Code Adapted from TutorialsTeacher.com, n.d.
                    output = new ArrayList { theLocation, totalCamerasOnline, totalCameras, theLocation.CurrentPeopleCount };

                    return Ok(output);
                }
            }
            catch (Exception e)
            {
                return Content(HttpStatusCode.NotFound, "- API Error " + e + " -");
            }
        }

        [HttpGet, HttpPut]
        [Route("UpdateSurveillance")]
        public IHttpActionResult UpdateSurveillance(int locationID, string locationName, string locationDescription)
        {
            try
            {
                userLocationSurveillanceTable theLocation = theEntity.userLocationSurveillanceTables.FirstOrDefault(location => location.locationID == locationID);
                if (theLocation == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Location Not Found -");
                }
                else
                {
                    theLocation.locationName = locationName;
                    theLocation.locationDescription = locationDescription;
                    theEntity.SaveChanges();
                    return Ok("- Successfully Updated the Surveillance Location -");
                }
            }
            catch (Exception e)
            {
                return Content(HttpStatusCode.NotFound, "- API Error " + e + " -");
            }
        }

        [HttpGet, HttpDelete]
        [Route("DeleteSurveillance")]
        public IHttpActionResult DeleteSurveillance(int userID, int locationID)
        {
            try
            {
                // Verify the Location ID
                userLocationSurveillanceTable theLocation = theEntity.userLocationSurveillanceTables.FirstOrDefault(location => location.userID == userID && location.locationID == locationID);
                if (theLocation == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Location Not Found -");
                }

                

                // Delete The Cameras First
                userCameraTable[] cameras = theEntity.userCameraTables.Where(camera => camera.locationID == locationID).ToArray();
                for (int i = 0; i < cameras.Length; i++)
                {
                    // Delete Other Cameras Childs First
                    var camID = cameras[i].cameraID;
                    cameraMarksCoordinate[] marks = theEntity.cameraMarksCoordinates.Where(mark => mark.cameraID == camID).ToArray();
                    if (marks.Length != 0)
                    {
                        theEntity.cameraMarksCoordinates.RemoveRange(marks);
                        theEntity.SaveChanges();
                    }

                    webStreamSignalTable stream = theEntity.webStreamSignalTables.FirstOrDefault(str => str.cameraID == camID);
                    if (stream != null)
                    {
                        theEntity.webStreamSignalTables.Remove(stream);
                        theEntity.SaveChanges();
                    }


                    cameraStreamTable stream2 = theEntity.cameraStreamTables.FirstOrDefault(str => str.cameraID == camID);
                    if (stream2 != null)
                    {
                        theEntity.cameraStreamTables.Remove(stream2);
                        theEntity.SaveChanges();
                    }
                }

                theEntity.userCameraTables.RemoveRange(cameras);
                theEntity.SaveChanges();


                // Delete recordPeopleCountTable
                recordPeopleCountTable[] records = theEntity.recordPeopleCountTables.Where(rec => rec.locationID == locationID).ToArray();
                theEntity.recordPeopleCountTables.RemoveRange(records);

                // Then Delete the Location
                string outputSTR = theLocation.locationName;
                theEntity.userLocationSurveillanceTables.Remove(theLocation);
                theEntity.SaveChanges();
                return Ok(outputSTR);               

        }
            catch 
            {
                return Content(HttpStatusCode.NotFound, "- Surveillance Location Failed to be Removed -");
            }
        }

        [HttpGet, HttpPost]
        [Route("AddCamera")]
        public IHttpActionResult AddCamera(int userID, int locationID, string cameraName, string cameraDescription, string cameraCode, int operationStatus)
        {
            try
            {
                // Verify the Location ID
                userLocationSurveillanceTable theLocation = theEntity.userLocationSurveillanceTables.FirstOrDefault(location => location.userID == userID && location.locationID == locationID);
                if (theLocation == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Location Not Found -");
                }

                // Add Camera
                userCameraTable newCamera = new userCameraTable();
                newCamera.locationID = locationID;
                newCamera.cameraCode = cameraCode;
                newCamera.cameraName = cameraName;
                newCamera.cameraDescription = cameraDescription;
                newCamera.operationStatus = operationStatus;
                newCamera.operatingStatus = 0;
                newCamera.streamStatus = 0;
                theEntity.userCameraTables.Add(newCamera);
                theEntity.SaveChanges();

                return Ok("- Surveillance Camera Succcessfully Added -");
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Surveillance Camera Failed to be Added -");
            }
        }

        [HttpGet]
        [Route("GetCamera")]
        public IHttpActionResult GetCamera(int cameraID)
        {
            try
            {
                userCameraTable theCamera = theEntity.userCameraTables.FirstOrDefault(camera => camera.cameraID == cameraID);
                if (theCamera == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Camera Not Found -");
                }
                else
                {
                    return Ok(theCamera);
                }
            }
            catch (Exception e)
            {
                return Content(HttpStatusCode.NotFound, "- API Error " + e + " -");
            }
        }

        [HttpGet, HttpPut]
        [Route("UpdateCamera")]
        public IHttpActionResult UpdateCamera(int cameraID, string cameraName, string cameraDescription, string cameraCode, int operationStatus)
        {
            try
            {
                userCameraTable theCamera = theEntity.userCameraTables.FirstOrDefault(camera => camera.cameraID == cameraID);
                if (theCamera == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Camera Not Found -");
                }

                theCamera.cameraCode = cameraCode;
                theCamera.cameraName = cameraName;
                theCamera.cameraDescription = cameraDescription;
                theCamera.operationStatus = operationStatus;
                theEntity.SaveChanges();

                return Ok("- Surveillance Camera Successfully Updated -");
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Surveillance Camera Failed to be Updated -");
            }
        }

        [HttpGet]
        [Route("RefreshCameras")]
        public IHttpActionResult RefreshCameras(int locationID, int sort)
        {
            try
            {

                var SQLScript = "";
                switch (sort)
                {
                    case (1):
                        SQLScript = "select * from userCameraTable where locationID='" + locationID + "' ORDER BY cameraName ASC";
                        break;
                    case (2):
                        SQLScript = "select * from userCameraTable where locationID='" + locationID + "' ORDER BY cameraName DESC";
                        break;
                    case (3):
                        SQLScript = "select * from userCameraTable where locationID='" + locationID + "' ORDER BY operatingStatus DESC";
                        break;
                    case (4):
                        SQLScript = "select * from userCameraTable where locationID='" + locationID + "' ORDER BY operatingStatus ASC";
                        break;
                    default:
                        SQLScript = "select * from userCameraTable where locationID='" + locationID + "' ORDER BY cameraName ASC";
                        break;
                }
                // End of Code Adapted

                var cameras = theEntity.Database.SqlQuery<userCameraTable>(SQLScript).ToList();
                return Ok(cameras);
            }
            catch (Exception e)
            {
                return Content(HttpStatusCode.NotFound, "- API Error " + e + " -");
            }
        }

        [HttpGet, HttpPost]
        [Route("GetNewCameraCode")]
        public IHttpActionResult GetNewCameraCode()
        {
            // Doing while loop until a new unique code are generated to avoid duplicated codes.
            while (true)
            {
                string codeCheck = validationCodeGenerator(15);
                userCameraTable camera = theEntity.userCameraTables.FirstOrDefault(cam => cam.cameraCode == codeCheck);
                if (camera == null)
                {
                    return Ok(codeCheck);
                }
            }
            
        }

        [HttpGet, HttpDelete]
        [Route("DeleteCamera")]
        public IHttpActionResult DeleteCamera(int locationID, int cameraID)
        {
            try
            {
                userCameraTable theCamera = theEntity.userCameraTables.FirstOrDefault(camera => camera.locationID == locationID && camera.cameraID == cameraID);
                if (theCamera == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Camera Not Found -");
                }

                List<cameraMarksCoordinate> marks = theEntity.cameraMarksCoordinates.Where(mark => mark.cameraID == cameraID).ToList();
                if (marks.Count != 0)
                {
                    theEntity.cameraMarksCoordinates.RemoveRange(marks);
                    theEntity.SaveChanges();
                }
                
                webStreamSignalTable stream = theEntity.webStreamSignalTables.FirstOrDefault(str => str.cameraID == cameraID);
                if (stream != null)
                {
                    theEntity.webStreamSignalTables.Remove(stream);
                    theEntity.SaveChanges();
                }
                

                cameraStreamTable stream2 = theEntity.cameraStreamTables.FirstOrDefault(str => str.cameraID == cameraID);
                if (stream2 != null)
                {
                    theEntity.cameraStreamTables.Remove(stream2);
                    theEntity.SaveChanges();
                }
                
                string outputSTR = theCamera.cameraName;
                theEntity.userCameraTables.Remove(theCamera);
                theEntity.SaveChanges();
                return Ok(outputSTR);
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Surveillance Camera Failed to be Removed -");
            }
        }

        [HttpGet, HttpPost]
        [Route("CheckServerStatus")]
        public IHttpActionResult CheckServerStatus()
        {
            return Ok();
        }


        [HttpGet, HttpPut]
        [Route("ToggleCameraOperation")]
        public IHttpActionResult ToggleCameraOperation(int cameraID, int status)
        {
            try
            {
                userCameraTable camera = theEntity.userCameraTables.Find(cameraID);
                if (camera == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Camera ID Incorrect -");
                }

                string statusStr = "";

                if (status == 1)
                {
                    camera.operationStatus = status;
                    theEntity.SaveChanges();
                    statusStr = "On";
                }
                else if (status == 0)
                {
                    camera.operationStatus = status;
                    theEntity.SaveChanges();
                    statusStr = "Off";
                }
                else
                {
                    statusStr = "WrongStatus";
                }


                return Ok("- " + camera.cameraName + " Camera Turned " + statusStr + " -");
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Update Camera Failed -");
            }

        }

        [HttpGet, HttpPut]
        [Route("ToggleCameraOperating")]
        public IHttpActionResult ToggleCameraOperating(int cameraID, int status)
        {
            try
            {
                userCameraTable camera = theEntity.userCameraTables.Find(cameraID);
                if (camera == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Camera ID Incorrect -");
                }

                string statusStr = "";

                if (status == 1)
                {
                    camera.operatingStatus = status;
                    theEntity.SaveChanges();
                    statusStr = "On";
                }
                else if (status == 0)
                {
                    camera.operatingStatus = status;
                    theEntity.SaveChanges();
                    statusStr = "Off";
                }
                else
                {
                    statusStr = "WrongStatus";
                }


                return Ok("- " + camera.cameraName + " Camera Turned " + statusStr + " -");
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Update Camera Failed -");
            }

        }

        [HttpGet, HttpPut]
        [Route("OnCameraStream")]
        public IHttpActionResult OnCameraStream(int cameraID)
        {
            try
            {
                userCameraTable camera = theEntity.userCameraTables.FirstOrDefault(cam => cam.cameraID == cameraID);
                if (camera == null)
                {
                    return NotFound();
                }
                camera.streamStatus = 1;
                theEntity.SaveChanges();
                return Ok();
            }
            catch
            {
                return NotFound();
            }

        }

        [HttpGet, HttpPut]
        [Route("OffCameraStream")]
        public IHttpActionResult OffCameraStream(int cameraID)
        {
            try
            {
                userCameraTable camera = theEntity.userCameraTables.FirstOrDefault(cam => cam.cameraID == cameraID);
                if (camera == null)
                {
                    return NotFound();
                }
                camera.streamStatus = 0;
                theEntity.SaveChanges();
                return Ok();
            }
            catch
            {
                return NotFound();
            }

        }

        [HttpGet, HttpPost, HttpPut, HttpDelete]
        [Route("PostStreamInput")]
        public IHttpActionResult PostStreamInput(int cameraID)
        {
            try
            {
                HttpPostedFile theImage = HttpContext.Current.Request.Files[0];

                byte[] output;

                using (BinaryReader br = new BinaryReader(theImage.InputStream))
                {
                    output = br.ReadBytes(theImage.ContentLength);
                }

                cameraStreamTable streams = theEntity.cameraStreamTables.FirstOrDefault(stream => stream.cameraID == cameraID);
                if (streams != null)
                {
                    streams.imageEncoded = output;
                    streams.timeStreamed = DateTime.UtcNow;
                    theEntity.SaveChanges();
                } else
                {
                    cameraStreamTable newStream = new cameraStreamTable();
                    newStream.cameraID = cameraID;
                    newStream.imageEncoded = output;
                    newStream.timeStreamed = DateTime.UtcNow;
                    theEntity.cameraStreamTables.Add(newStream);
                    theEntity.SaveChanges();
                }

                webStreamSignalTable signalCheck = theEntity.webStreamSignalTables.FirstOrDefault(sig => sig.cameraID == cameraID);
                if (signalCheck != null)
                {
                    DateTime now = DateTime.UtcNow;
                    System.TimeSpan timeDifference = now.Subtract(signalCheck.timeSignaled);
                    // 2 minutes no update, stop stream
                    // Signal will always be update with real time if they are receiving the stream images.
                    if (timeDifference.TotalMinutes > 2)
                    {
                        userCameraTable theCam = theEntity.userCameraTables.Find(cameraID);
                        theCam.streamStatus = 0;
                        theEntity.SaveChanges();
                    }
                } else
                {
                    userCameraTable theCam = theEntity.userCameraTables.Find(cameraID);
                    theCam.streamStatus = 0;
                    theEntity.SaveChanges();
                }
                return Ok();
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Stream Upload Failed -");

            }

        }

        [HttpGet, HttpPost, HttpPut]
        [Route("GetStreamInput")]
        public IHttpActionResult GetStreamInput(int cameraID)
        {
            try
            {
                cameraStreamTable streams = theEntity.cameraStreamTables.FirstOrDefault(stream => stream.cameraID == cameraID);
                if (streams == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Streams not Found -");
                }

                webStreamSignalTable updateSignal = theEntity.webStreamSignalTables.FirstOrDefault(signal => signal.cameraID == cameraID);
                if (updateSignal != null)
                {
                    updateSignal.timeSignaled = System.DateTime.UtcNow;
                    theEntity.SaveChanges();
                } else
                {
                    webStreamSignalTable firstSignal = new webStreamSignalTable();
                    firstSignal.cameraID = cameraID;
                    firstSignal.timeSignaled = System.DateTime.UtcNow;
                    theEntity.webStreamSignalTables.Add(firstSignal);
                    theEntity.SaveChanges();                        
                }
                return Ok(streams.imageEncoded);
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Stream Retrieving Failed -");

            }

        }

        [HttpGet, HttpPost, HttpDelete]
        [Route("UploadMarks")]
        public IHttpActionResult UploadMarks(int cameraID)
        {
            try
            {
                userCameraTable camera = theEntity.userCameraTables.FirstOrDefault(cam => cam.cameraID == cameraID);
                if (camera == null)
                {
                    return Content(HttpStatusCode.NotFound, " - Camera Not Found -");
                }

                // Delete old Cords First if camera is old
                cameraMarksCoordinate[] checkExist = theEntity.cameraMarksCoordinates.Where(cam => cam.cameraID == cameraID).ToArray();
                if (checkExist.Length != 0)
                {
                    theEntity.cameraMarksCoordinates.RemoveRange(checkExist);
                    theEntity.SaveChanges();
                }

                // Read File
                var enterCordsExt = HttpContext.Current.Request.Files[0];
                
                // Read file as Text
                string enterCordSTR = (new StreamReader(enterCordsExt.InputStream)).ReadToEnd();

                // Convert String to Char[] to clean the data
                char[] enterChar = enterCordSTR.ToCharArray();
                string enterFinalSTR = "";
                for (int i = 0; i < enterChar.Length; i++)
                {
                    if (Char.IsDigit(enterChar[i]) || enterChar[i] == ' ' || enterChar[i] == ',')
                    {
                        enterFinalSTR += enterChar[i].ToString();
                    }
                }

                // Now Split sets of cords by ",".
                string[] enterSplit = enterFinalSTR.Split(',').ToArray();


                var exitCordsExt = HttpContext.Current.Request.Files[1];
                string exitCordSTR = (new StreamReader(exitCordsExt.InputStream)).ReadToEnd();
                char[] exitChar = exitCordSTR.ToCharArray();
                string exitFinalSTR = "";
                for (int i = 0; i < exitChar.Length; i++)
                {
                    if (Char.IsDigit(exitChar[i]) || exitChar[i] == ' ' || exitChar[i] == ',')
                    {
                        exitFinalSTR += exitChar[i].ToString();
                    }
                }
                string[] exitSplit = exitFinalSTR.Split(',').ToArray();


                // Add Enter Cords
                for (int i = 0; i < enterSplit.Length; i++)
                {
                    if (enterSplit[i] != "")
                    {
                        string[] split = enterSplit[i].Split(' ').ToArray();
                        cameraMarksCoordinate newCord = new cameraMarksCoordinate();
                        newCord.cameraID = cameraID;
                        newCord.cordXStart = int.Parse(split[0]);
                        newCord.cordYStart = int.Parse(split[1]);
                        newCord.cordXEnd = int.Parse(split[2]);
                        newCord.cordYEnd = int.Parse(split[3]);
                        newCord.markType = 1;
                        theEntity.cameraMarksCoordinates.Add(newCord);
                        theEntity.SaveChanges();
                    }                    
                }
                
                // Add Exit Cords
                for (int i = 0; i < exitSplit.Length; i++)
                {
                    if (exitSplit[i] != "")
                    {
                        string[] split = exitSplit[i].Split(' ').ToArray();
                        cameraMarksCoordinate newCord = new cameraMarksCoordinate();
                        newCord.cameraID = cameraID;
                        newCord.cordXStart = int.Parse(split[0]);
                        newCord.cordYStart = int.Parse(split[1]);
                        newCord.cordXEnd = int.Parse(split[2]);
                        newCord.cordYEnd = int.Parse(split[3]);
                        newCord.markType = 0;
                        theEntity.cameraMarksCoordinates.Add(newCord);
                        theEntity.SaveChanges();
                    }
                }

                return Ok(" - Marks successfully Saved -");
            }
            catch
            {
                return Content(HttpStatusCode.NotFound, "- Marks Save failed -");
                
            }
            
        }

        [HttpGet, HttpPost]
        [Route("RetrieveMarks")]
        public IHttpActionResult RetrieveMarks(int cameraID)
        {
            try
            {


                userCameraTable camera = theEntity.userCameraTables.FirstOrDefault(cam => cam.cameraID == cameraID);
                if (camera == null)
                {
                    //return Request.CreateResponse(HttpStatusCode.NotFound, "- Camera Not Found -");
                    return Content(HttpStatusCode.NotFound, " - Marks upload failed -");
                }

                cameraMarksCoordinate checkExist = theEntity.cameraMarksCoordinates.FirstOrDefault(cam => cam.cameraID == cameraID);
                if (checkExist == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Please Add Marks -");
                }

                cameraMarksCoordinate[] cords = theEntity.cameraMarksCoordinates.Where(cord => cord.cameraID == cameraID).ToArray();
                
                return Ok(cords);
            }
            catch
            {
                //return Request.CreateResponse(HttpStatusCode.NotFound, "- Marks retrieved failed -");
                return Content(HttpStatusCode.NotFound, "- Marks retrieved failed -");
            }

        }

        [HttpGet]
        [Route("LoginCamera")]
        public IHttpActionResult LoginCamera(string cameraCode)
        {
            try
            {
                userCameraTable theCamera = theEntity.userCameraTables.FirstOrDefault(camera => camera.cameraCode == cameraCode);
                if (theCamera == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Camera Not Found -");
                }
                else
                {
                    return Ok(theCamera);
                }
            }
            catch (Exception e)
            {
                return Content(HttpStatusCode.NotFound, "- API Error " + e + " -");
            }
        }

        [HttpGet, HttpPost, HttpPut]
        [Route("CameraUpdateRecordOfLocation")]
        public IHttpActionResult CameraUpdateRecordOfLocation(int cameraID, bool count)
        {
            try
            {
                userCameraTable theCamera = theEntity.userCameraTables.FirstOrDefault(camera => camera.cameraID == cameraID);
                if (theCamera == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Camera Not Found -");
                }
                else
                {
                    userLocationSurveillanceTable theLocation = theEntity.userLocationSurveillanceTables.FirstOrDefault(loc => loc.locationID == theCamera.locationID);
                    if (theLocation == null)
                    {
                        return Content(HttpStatusCode.NotFound, "- Surveillance Location Not Found -");
                    }
                    else
                    {
                        int currentCount;
                        recordPeopleCountTable[] thelatest = theEntity.recordPeopleCountTables.Where(record => record.locationID == theCamera.locationID).OrderByDescending(rec => rec.timeRecorded).ToArray();

                        if (thelatest.Length != 0)
                        {
                            // Code adapted from net-informations.com, n.d.
                            DateTime day = Convert.ToDateTime(thelatest[0].timeRecorded);
                            // End of code adapted.
                            DateTime now = DateTime.UtcNow;
                            

                            if (day.Day != now.Day)
                            {
                                // New Day resets.
                                currentCount = 0;

                            }
                            else
                            {
                                currentCount = (int)theLocation.CurrentPeopleCount;

                            }
                        }
                        else
                        {
                            currentCount = (int)theLocation.CurrentPeopleCount;

                        }

                        if (count)
                        {
                            currentCount += 1;
                        }
                        else
                        {
                            currentCount -= 1;
                        }
                        theLocation.CurrentPeopleCount = currentCount;
                        theEntity.SaveChanges();

                        recordPeopleCountTable newRecord = new recordPeopleCountTable();
                        newRecord.locationID = theLocation.locationID;
                        newRecord.PeopleCount = (int)theLocation.CurrentPeopleCount;
                        newRecord.timeRecorded = DateTime.UtcNow;
                        theEntity.recordPeopleCountTables.Add(newRecord);
                        theEntity.SaveChanges();
                        return Ok(" - Record Update Successfully -");
                    }

                }
            }
            catch (Exception e)
            {
                return Content(HttpStatusCode.NotFound, "- API Error " + e + " -");
            }
        }

        [HttpGet]
        [Route("GetLocationRecords")]
        public IHttpActionResult GetLocationRecords(int locationID)
        {
            try
            {
                userLocationSurveillanceTable theLocation = theEntity.userLocationSurveillanceTables.FirstOrDefault(loc => loc.locationID == locationID);
                if (theLocation == null)
                {
                    return Content(HttpStatusCode.NotFound, "- Surveillance Location Not Found -");
                }
                // Code adapted from E. Jim, 2021.
                var SQLScript = "declare @currentDate DATE = getdate(); select *, cast(cast(timeRecorded as smalldatetime) as time) as TimeOnly from recordPeopleCountTable where locationID = '" + locationID + "' and cast(timeRecorded as Date) = @currentDate";
                // End of Code Adapted.
                var output = theEntity.Database.SqlQuery<recordPeopleCountTable>(SQLScript).ToList();
                ArrayList finalOutput = new ArrayList();
                finalOutput.Add(theLocation.locationName);
                finalOutput.Add(output);
                return Ok(finalOutput);
            }
            catch (Exception e)
            {
                return Content(HttpStatusCode.NotFound, "- API Error " + e + " -");
            }
        }


        private string validationCodeGenerator(int numberChar)
        {
            string theCode = "";
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            Random random = new Random();            
            for (int i = 0; i < numberChar; i++)
            {
                int randomChar = random.Next(0, chars.Length);
                theCode += chars[randomChar];
            }
            return theCode;
        }

        public static string HashPassword(string password)
        {
            byte[] salt;
            byte[] buffer2;
            if (password == null)
            {
               throw new ArgumentNullException("password");
            }
            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, 0x10, 0x3e8))
            {
                salt = bytes.Salt;
                buffer2 = bytes.GetBytes(0x20);
            }
            byte[] dst = new byte[0x31];
            Buffer.BlockCopy(salt, 0, dst, 1, 0x10);
            Buffer.BlockCopy(buffer2, 0, dst, 0x11, 0x20);
            return Convert.ToBase64String(dst);
            
        }

        public static bool VerifyHashedPassword(string hashedPassword, string password)
        {
            byte[] buffer4;
            if (hashedPassword == null)
            {
                return false;
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            byte[] src = Convert.FromBase64String(hashedPassword);
            if ((src.Length != 0x31) || (src[0] != 0))
            {
                return false;
            }
            byte[] dst = new byte[0x10];
            Buffer.BlockCopy(src, 1, dst, 0, 0x10);
            byte[] buffer3 = new byte[0x20];
            Buffer.BlockCopy(src, 0x11, buffer3, 0, 0x20);
            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, dst, 0x3e8))
            {
                buffer4 = bytes.GetBytes(0x20);
            }
            //Code Adapted From Aku(Sept 4, 2008)
            return buffer3.SequenceEqual(buffer4);
        }


    }



    
}