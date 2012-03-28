using System;
using System.Collections.Generic;
using System.Text;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;

namespace block_spam_ips
{
    class Program
    {
        struct FoundInLog
        {
            public string IP4Detected;
            public DateTime DateLastSeen;
            public int InstanceCount;
        }

        enum ErrorLevel
        {
            ErrFirewall = 1,
            ErrScheduler = 2,
            ErrLogParser = 3,
            ErrNetShell = 4,
            ErrSQLiteDB = 5,
            ErrInputOutput = 6,
            ErrFilePermission = 7
        };

        private static List<FoundInLog> spmrs = new List<FoundInLog>();
        private static string currdir = "";
        private static string mydb = "";
        private static bool bdebug = false;

        static int Main(string[] args)
        {
            bool binst = false;
            bool bdelete = false;
            bool bnorun = false;

            string evtid = "4625"; //The ID in the Security Log for the event that we're looking for ("An account failed to log on.")
            string evtrshld = "10"; //adjust this number to determine what should be the threshold for the max # of failed events before an IP is flagged

            currdir = Directory.GetCurrentDirectory();
            
            //check directory write permissions as the first step. If we can't output the netsh script, we can't be useful.
            if (!HasFilePermissions())
            {
                Console.WriteLine("You don't have the required file access permissions to run this application.");
                return (int)ErrorLevel.ErrFilePermission;
            }

            mydb = "Data Source=\"" + currdir + "\\bannedips.dat\";Version=3;";

            if (args.Length > 0) //check args for "--install", "--remove", "--norun" or "--debug"
            {
               foreach (string s in args)
               {
                   switch(s.ToLower()) {
                       case "--debug":
                           bdebug = true; break; 
                       case "--install":
                           binst = true; break; 
                       case "--remove":
                           bdelete = true; break;
                       case "--norun":
                           bnorun = true; break;

                   }
                }
               if (binst && bdelete)  //if providing both install & delete options
               {
                   OutputMsg("Options --install and --remove are mutually exclusive. Please choose only one.");
                   return 0;
               }
            }

            if (bdebug) OutputMsg("SQLite DB Connection String: " + mydb);

            if (binst) //original setup for firewall rule and scheduled task
            {
                //check to see if the rule is already there. We don't want to have extra copies
                if (!FirewallRuleExists())
                {
                    if (!AddFirewallRule())  //now add the rule if it's not already there
                    {
                        OutputMsg("Failed creating the firewall rule to block IPs. Unable to continue.");
                        return (int)ErrorLevel.ErrFirewall;
                    }
                }

                if (!ScheduleTask())  //now add scheduled task, if exists it will be overwritten
                {
                    OutputMsg("Failed creating a scheduled task to update list of blocked IP addresses. Unable to continue.");
                    return (int)ErrorLevel.ErrScheduler;
                }
               
                //it will continue to run once after the installation unless "--norun" is specified
                if (bnorun)
                {
                    OutputMsg("Installation was successful. Exiting app until next scheduled run.");
                    return 0;
                }
            }

            if (bdelete)   //remove firewall rule and the scheduled task (if they exist), then exit the app
            {
                if (!DeleteFirewallRule())
                {
                    OutputMsg("Failed deleting the firewall rule: \"Banned IP Addresses\". Unable to continue.");
                    return (int)ErrorLevel.ErrFirewall;
                }

                if (!RemoveScheduledTask())
                {
                    OutputMsg("Failed removing the scheduled task to update banned IP address list. Unable to continue.");
                    return (int)ErrorLevel.ErrScheduler;
                }
                OutputMsg("Scheduled System Task and Firewall Rule are now uninstalled.");
                return 0;
            }

            //we're starting the scheduled run. It could be happening without required installation
            if (!binst && !FirewallRuleExists()) //skip if right after installation
            {
                OutputMsg("Firewall rule not found. Run the app with \"--install\" parameter to set it up.");
                return (int)ErrorLevel.ErrFirewall;
            }

            //get records from the Security Logs
            try
            {
                MSUtil.LogQueryClass lq = new MSUtil.LogQueryClass();
                MSUtil.ILogRecordset rs = lq.Execute("SELECT EXTRACT_TOKEN(Strings, 19, '|') AS [IP4Detected], MAX(TimeWritten) AS [DateLastSeen]," +
                    " COUNT(*) AS [InstanceCount] FROM Security WHERE EventID=" + evtid + 
                    " AND TimeWritten>SUB(TO_LOCALTIME(SYSTEM_TIMESTAMP()), TIMESTAMP('0000-01-01 23:59:59', 'yyyy-MM-dd HH:mm:ss'))" +
                    " GROUP BY EXTRACT_TOKEN(Strings, 19, '|') HAVING COUNT(*)>" + evtrshld);
                while (!rs.atEnd())
                {
                    MSUtil.ILogRecord rec = rs.getRecord();

                    FoundInLog tmp = new FoundInLog();
                    tmp.IP4Detected = rec.getValue(0);
                    tmp.DateLastSeen = rec.getValue(1);
                    tmp.InstanceCount = rec.getValue(2);

                    spmrs.Add(tmp);

                    if (bdebug) OutputMsg(tmp.IP4Detected.ToString() + ", " + tmp.DateLastSeen.ToShortDateString() + ", " + tmp.InstanceCount.ToString());
                    rs.moveNext();
                }

                if (spmrs.Count == 0)
                {
                    OutputMsg("Run successfully completed, no new records were found.");
                    return 0;
                }
            }
            catch (Exception e)
            {
                OutputMsg("Unable to query Event Log. Make sure LogParser is installed (see README for details)." , e.ToString());
                return (int)ErrorLevel.ErrLogParser;
            }

            //add the new records to the local sqlite3 database
            if (!UpdateDBRecords())
            {
                OutputMsg("Problem writing to the \"bannedips.dat\" database");
                return (int)ErrorLevel.ErrSQLiteDB;
            }

            //export updated records to a script file to be used with netsh
            if (!ExportDBRecords())
            {
                OutputMsg("Problem writing to the netsh script file");
                return (int)ErrorLevel.ErrInputOutput;
            }

            //replace IP list in the firewall rule with the new set from the DB
            if (!UpdateFirewallRule())
            {
                OutputMsg("Problem calling netsh.exe to update firewall rule.");
                return (int)ErrorLevel.ErrNetShell;
            }


            //final step - record our activity
            if (!StampLastRun())
            {
                //nothing to do
            }

            //every step is nicely completed. Report success and be done.
            OutputMsg("IP Address Blacklist was successfully updated with data from last 24 hours.");
            return 0;
        }

        static bool ScheduleTask()
        {
            //update XML file with current directory info
            string taskxml = "";

            try
            {
                using (TextReader cfgfile = File.OpenText(currdir + "\\Update Blacklisted IP Addresses.xml"))
                {
                    taskxml = cfgfile.ReadToEnd();
                }

                taskxml = taskxml.Replace("%CURRENT_DIR%", currdir);
                File.WriteAllText(currdir + "\\Update Blacklisted IP Addresses.xml", taskxml);
            }
            catch (Exception e)
            {
                OutputMsg("Couldn't read or write to \"Update Blacklisted IP Addresses.xml\" file. Make sure it's in the current folder.", e.ToString());
                return false;
            }

            //accomplished via shelling out to schtasks.exe with relevant arguments.
            Process proc = new Process();
            proc.EnableRaisingEvents = false;
            proc.StartInfo.UseShellExecute = false; //the process should be created directly from this app.
            proc.StartInfo.RedirectStandardError = true; //allowed since we set UseShellExecute to false
            proc.StartInfo.FileName = "schtasks.exe"; //would include the folder name if not in system path
            proc.StartInfo.Arguments = "/create /tn \"Update Blacklisted IP Addresses\" /F /XML \"Update Blacklisted IP Addresses.xml\"";
            proc.StartInfo.CreateNoWindow = true;
            string errstr = "";

            try
            {
                OutputMsg("Starting Windows Task Scheduler to add a daily job.");
                proc.Start();
                errstr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
            }
            catch (Exception e)
            {
                OutputMsg("Error starting Task Scheduler (schtasks.exe)" , e.ToString());
                proc.Dispose();
                return false;
            }

            if (errstr != "")
            {
                //we got an unexpected response but will treat it as conditional success
                OutputMsg("Suspicious output from schtasks.exe:\n\t" + errstr +
                                "\n*** Check to verify that the task was scheduled correctly. ***");
            }

            //return the file to its original shape, in case we need to reinstall from a different folder
            taskxml = taskxml.Replace(currdir, "%CURRENT_DIR%");
            File.WriteAllText(currdir + "\\Update Blacklisted IP Addresses.xml", taskxml);

            proc.Dispose();
            return true;
        }

        static bool RemoveScheduledTask()
        {
            //accomplished via shelling out to schtasks.exe with relevant arguments.
            Process proc = new Process();
            proc.EnableRaisingEvents = false;
            proc.StartInfo.UseShellExecute = false; //the process should be created directly from this app.
            proc.StartInfo.RedirectStandardError = true; //allowed since we set UseShellExecute to false
            proc.StartInfo.FileName = "schtasks.exe"; //would include the folder name if not in system path
            proc.StartInfo.Arguments = "/delete /tn \"Update Blacklisted IP Addresses\" /F";
            proc.StartInfo.CreateNoWindow = true;
            string errstr = "";

            try
            {
                OutputMsg("Starting Windows Task Scheduler to remove daily job.");
                proc.Start();
                errstr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
            }
            catch (Exception e)
            {
                OutputMsg("Uninstall error -- failed to remove scheduled task" , e.ToString());
                proc.Dispose();
                return false;
            }

            if (errstr != "" && // These two errors are acceptable for this action
                !errstr.Contains("The specified task name \"Update Blacklisted IP Addresses\" does not exist") &&
                !errstr.Contains("ERROR: The system cannot find the file specified."))
            {
                //otherwise, we got an unexpected response but will treat it as conditional success
                OutputMsg("Suspicious output from schtasks.exe:\n\t" + errstr +
                                "\n*** Check to verify that the task was removed correctly. ***");
            }

            proc.Dispose();
            return true;
        }

        static bool UpdateDBRecords()
        {
            SQLiteConnection cn = null;
            try
            {
                cn = new SQLiteConnection(mydb);
                cn.Open();
            }
            catch (Exception e)
            {
                OutputMsg("Can't open the local database. Make sure \"bannedips.dat\" is in the current folder." , e.ToString());
                return false;
            }

            string sql = "";
            bool b = false;

            //add new records to temp table
            foreach (var t in spmrs)
            {
                sql = "INSERT INTO TEMP_RECS(IP4Instance, DateLastSeen, FailedAttempts) VALUES('" +
                    t.IP4Detected + "','" + t.DateLastSeen.ToString("yyyy-MM-dd HH:mm:ss")  + "'," + t.InstanceCount + ")";
                b = ExecuteQuery(cn, sql);
                if (b == false)
                {
                    cn.Close();
                    cn.Dispose();
                    return false;
                }
            }

            //append the valid temp records
            sql = @"insert into IP4DETECTED 
                        select IP4Instance, FailedAttempts,
	                    case when IP4Instance like '%.%.%.___' then substr(IP4Instance, 1, length(IP4Instance)-3) || '0' 
	                         when IP4Instance like '%.%.%.__' then substr(IP4Instance, 1, length(IP4Instance)-2) || '0' 
	                         when IP4Instance like '%.%.%._' then substr(IP4Instance, 1, length(IP4Instance)-1) || '0' 
	                    end, 
	                    datetime('now')
                        from TEMP_RECS where IP4Instance not in (Select IP4Instance from IP4Detected);";

            b = ExecuteQuery(cn, sql);
            if (b == false)
            {
                cn.Close();
                cn.Dispose();
                return false;
            }

            //update master list of IPs
            sql = @"update IP4DETECTED 
                        set FailedAttempts = FailedAttempts + 
	                    (select FailedAttempts from TEMP_RECS where IP4DETECTED.IP4Instance = TEMP_RECS.IP4Instance),
	                    DateLastSeen = (select DateLastSeen from TEMP_RECS where IP4DETECTED.IP4Instance = TEMP_RECS.IP4Instance)
                        where IP4Instance in 
	                    (select IP4Instance from TEMP_RECS where IP4DETECTED.IP4Instance = TEMP_RECS.IP4Instance and IP4DETECTED.DateLastSeen != TEMP_RECS.DateLastSeen);";
            b = ExecuteQuery(cn, sql);
            if (b == false)
            {
                cn.Close();
                cn.Dispose();
                return false;
            }

            //cleanup on aisle temp_recs
            sql = @"delete from TEMP_RECS;";
            b = ExecuteQuery(cn, sql);
            if (b == false)
            {
                cn.Close();
                cn.Dispose();
                return false;
            }

            cn.Close();
            cn.Dispose();
            return true;
        }

        static bool ExportDBRecords()
        {
            string sql = "select distinct IP4Subnet||configvalue from IP4DETECTED,CONFIG_VALUES where configtoken='IP4_SUBNET_MASK';";
            string scriptbody = "";
            string scriptheader = "advfirewall\r\nfirewall\r\nset rule name=\"Banned IP Addresses\" new remoteip=";

            try
            {
                SQLiteConnection cn = new SQLiteConnection(mydb);
                cn.Open();
                SQLiteCommand cmd = new SQLiteCommand(sql, cn);
                SQLiteDataReader sdr = cmd.ExecuteReader();

                if (!sdr.HasRows)
                {
                    OutputMsg("No IP addresses found in the blacklist.");
                    sdr.Dispose();
                    cmd.Dispose();
                    cn.Close();
                    cn.Dispose();
                    return false;
                }

                while (sdr.Read())
                {
                    scriptbody = scriptbody + sdr.GetString(0) + ",";
                }

                sdr.Dispose();
                cmd.Dispose();
                cn.Close(); 
                cn.Dispose();

                scriptbody = scriptheader + scriptbody.TrimEnd(',');

                //write it out to netsh_script.txt
                File.WriteAllText(currdir + "\\netsh_script.txt", scriptbody, Encoding.ASCII); //not UTF-8, ASCII behaves better on the command line
            }
            catch (SQLiteException se)
            {
                OutputMsg("Problem reading from bannedips.dat file." , se.ToString());
                return false;
            }
            catch (Exception e)
            {
                OutputMsg("Error while exporting data to local file." , e.ToString());
                return false;
            }

            return true;
        }

        static bool UpdateFirewallRule()
        {
            //accomplished via shelling out to netsh.exe and using a script file.
            Process proc = new Process();
            proc.EnableRaisingEvents = false;
            proc.StartInfo.UseShellExecute = false; //the process should be created directly from this app.
            proc.StartInfo.RedirectStandardError = true; //allowed since we set UseShellExecute to false
            proc.StartInfo.FileName = "netsh.exe"; //would include the folder name if not in system path
            proc.StartInfo.Arguments = "-f netsh_script.txt";
            proc.StartInfo.CreateNoWindow = true;
            string errstr = "";

            try
            {
                proc.Start();
                errstr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
            }
            catch (Exception e)
            {
                OutputMsg("Unable to update firewall rule. Error starting process for netsh.exe", e.ToString());
                proc.Dispose();
                return false;
            }

            if (errstr != "")
            {
                OutputMsg("Suspicious output from netsh.exe:\n\t" + errstr +
                                "\n*** Check to verify that the update was processed correctly. ***");
            }

            proc.Dispose();
            return true;
        }

        static bool ExecuteQuery(SQLiteConnection conn, string sql)
        {
            SQLiteCommand cmd = new SQLiteCommand(sql, conn);
            int i = 0;
            try
            {
                i = cmd.ExecuteNonQuery();
            }
            catch (SQLiteException se)
            {
                OutputMsg("Unable to execute the query: [" + sql + "]" , se.ToString());
                return false;
            }
            cmd.Dispose();
            return true;
        }

        static bool StampLastRun()
        {
            try
            {
                SQLiteConnection cn = new SQLiteConnection(mydb);
                cn.Open();
                string sql = @"update CONFIG_VALUES set priorvalue=configvalue, configvalue=datetime('now','localtime') where configtoken='LAST_RUN_DATE';";
                if (!ExecuteQuery(cn, sql)) return false;

                cn.Close();
            }
            catch (Exception e) {
                OutputMsg("The job was run successfully, but config_values were not updated.", e.ToString());
            } //
            return true; //we don't really care if this fails.
        }

        static bool AddFirewallRule()
        {
            //accomplished via shelling out to netsh.exe with relevant arguments.
            Process proc = new Process();
            proc.EnableRaisingEvents = false;
            proc.StartInfo.UseShellExecute = false; //the process should be created directly from this app.
            proc.StartInfo.RedirectStandardError = true; //allowed since we set UseShellExecute to false
            proc.StartInfo.FileName = "netsh.exe"; //would include the folder name if not in system path
            proc.StartInfo.Arguments = "advfirewall firewall add rule name=\"Banned IP Addresses\" dir=in action=block description=\"IPs detected from Security Event Log with more than 10 failed attempts a day\" enable=yes profile=any localip=any protocol=any interfacetype=any";
            proc.StartInfo.CreateNoWindow = true;
            string errstr = "";

            try
            {
                OutputMsg("Starting netsh.exe to add firewall rule");
                proc.Start();
                errstr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
            }
            catch (Exception e)
            {
                OutputMsg("Unable to add firewall rule. Error starting process for netsh.exe" , e.ToString());
                proc.Dispose();
                return false;
            }

            if (errstr != "")
            {
                OutputMsg("Suspicious output from netsh.exe:\n\t" + errstr +
                                "\n*** Check to verify that the update was processed correctly. ***");
             }

            proc.Dispose();
            return true;
        }

        static bool DeleteFirewallRule()
        {
            //accomplished via shelling out to netsh.exe with relevant arguments.
            Process proc = new Process();
            proc.EnableRaisingEvents = false;
            proc.StartInfo.UseShellExecute = false; //the process should be created directly from this app.
            proc.StartInfo.RedirectStandardError = true; //allowed since we set UseShellExecute to false
            proc.StartInfo.FileName = "netsh.exe"; //would include the folder name if not in system path
            proc.StartInfo.Arguments = "advfirewall firewall delete rule name=\"Banned IP Addresses\"";
            proc.StartInfo.CreateNoWindow = true;
            string errstr = "";

            try
            {
                OutputMsg("Starting netsh.exe to delete firewall rule.");
                proc.Start();
                errstr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
            }
            catch (Exception e)
            {
                Console.WriteLine("Error starting process for netsh.exe: " + e.ToString());
                proc.Dispose();
                return false;
            }

            if (errstr != "")
            {
                if (errstr.Contains("No rules match the specified criteria."))
                {
                    //rule doesn't exist
                    proc.Dispose();
                    return true;
                }
                else
                {
                    if (errstr.Contains("Deleted ") && errstr.Contains(" rule(s)."))
                    {
                        //rule successfully deleted. Multiple rules with the same name will all be gone
                        proc.Dispose();
                        return true;
                    }
                    else
                    {
                        //we got an unexpected response but will treat it as conditional success
                        OutputMsg("Suspicious output from netsh.exe:\n\t" + errstr +
                                        "\n*** Check to verify that the update was processed correctly. ***");
                    }
                }
            }

            proc.Dispose();
            return true;
        }

        static bool FirewallRuleExists()
        {
            //accomplished via shelling out to netsh.exe with relevant arguments.
            Process proc = new Process();
            proc.EnableRaisingEvents = false;
            proc.StartInfo.UseShellExecute = false; //the process should be created directly from this app.
            proc.StartInfo.RedirectStandardOutput = true; //allowed since we set UseShellExecute to false
            proc.StartInfo.FileName = "netsh.exe"; //would include the folder name if not in system path
            proc.StartInfo.Arguments = "advfirewall firewall show rule name=\"Banned IP Addresses\"";
            proc.StartInfo.CreateNoWindow = true;
            string errstr = "";

            try
            {
                OutputMsg("Checking to see if the firewall rule exists.");
                proc.Start();
                errstr = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();
            }
            catch (Exception e)
            {
                OutputMsg("Error starting process for netsh.exe" , e.ToString());
                proc.Dispose();
                return false;
            }

            if (errstr != "")
            {
                if (errstr.Contains("No rules match the specified criteria."))
                {
                    //rule doesn't exist
                    proc.Dispose();
                    return false;
                }
                else
                {
                    if (errstr.Contains("Rule Name:") && errstr.Contains("Banned IP Addresses\r\n")) {
                        //rule already exists
                        proc.Dispose();
                        return true; 
                    }
                    else
                    {
                        //we got an unexpected response but will treat it as conditional success
                        OutputMsg("Suspicious output from netsh.exe:\n\t" + errstr +
                                        "\n*** Check to verify that the update was processed correctly. ***");
                    }
                }

            }

            proc.Dispose();
            return true;
        }

        static bool HasFilePermissions()
        {
            string tmpfile = Directory.GetCurrentDirectory() + "\\tmpfile_" + DateTime.UtcNow.GetHashCode().ToString() + ".tmp";
            try
            {
                File.WriteAllText(tmpfile, "testdata");
                File.AppendAllText(tmpfile, "moretestdata");
                File.ReadAllText(tmpfile);
                File.Delete(tmpfile);
            }
            catch (Exception e)
            {
                OutputMsg("Unable to create local file -> Check File Access permissions" , e.ToString());
                return false;
            }
            return true; 
        }

        static void OutputMsg(string msg, string ex = "")
        {
            Console.WriteLine(msg);
            if (ex != "")
            {
                Console.WriteLine("Exception Info: " + ex);
            }

            if (bdebug)
            {
                File.AppendAllText(currdir + "\\debuglog.txt", DateTime.Now.ToString("HH:mm:ss.fff") + ">> " + msg + "\r\n");
                if (ex != "")
                {
                    File.AppendAllText(currdir + "\\debuglog.txt", "            >> Exception Info: " + ex + "\r\n");
                }
            }
        }
    }
}
