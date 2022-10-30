using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SetAdProperties
{
    internal class Ldapcoon
    {
        public static int Port;
        public static string DomainName;
        public static string DomainController;
        private static DirectorySearcher searcher = null;

        public static DirectorySearcher getSearch(string Domain, string DC, bool Ldaps, bool Kerberos)
        {
            if (searcher == null)
            {
                searcher = searchInit(Domain, DC, Ldaps, Kerberos);
            }
            return searcher;
        }

        private static DirectorySearcher searchInit(string Domain, string DC, bool Ldaps, bool Kerberos)
        {
            DirectoryEntry entry = getDirectoryEntry(Domain, DC, Ldaps, Kerberos);
            DirectorySearcher search = new DirectorySearcher(entry);
            return search;
        }


        public static DirectoryEntry getDirectoryEntry(string Domain, string DC, bool Ldaps, bool Kerberos)
        {
            DomainName = Domain ?? Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            DomainController = DC ?? DomainName;
            Port = Ldaps ? 636 : 389;
            DirectoryEntry entry;
            if (Ldaps)
            {
                entry = new DirectoryEntry($"LDAP://{DomainController}:{Port}", null, null, AuthenticationTypes.SecureSocketsLayer | AuthenticationTypes.Secure | AuthenticationTypes.Signing);
            }
            else
            {
                if (Kerberos)
                {
                    entry = new DirectoryEntry($"LDAP://{DomainController}:{Port}", null, null, AuthenticationTypes.Sealing | AuthenticationTypes.Secure | AuthenticationTypes.ServerBind | AuthenticationTypes.Signing);

                }
                else
                {
                    entry = new DirectoryEntry($"LDAP://{DomainController}:{Port}", null, null, AuthenticationTypes.Secure | AuthenticationTypes.ServerBind | AuthenticationTypes.Signing);
                }
            }
            return entry;
        }


        public static string FilterAddMatch(string filter)
        {
            return filter;
        }
        /// <summary>
        /// ldap查询所有信息
        /// </summary>
        /// <param name="filter"></param>
        /// <param name="sizeLimit"></param>
        /// <returns></returns>
        public static SearchResultCollection LdapSearchAll(string filter, int sizeLimit = 0)
        {
            filter = FilterAddMatch(filter);
            searcher.SizeLimit = sizeLimit;
            searcher.PageSize = 1000;
            searcher.Filter = filter;
            return searcher.FindAll();
        }

        /// <summary>
        /// ldap查询一条信息
        /// </summary>
        /// <param name="filter"></param>
        /// <param name="sizeLimit"></param>
        /// <returns></returns>
        public static SearchResult LdapSearchOne(string filter, int sizeLimit = 0)
        {
            filter = FilterAddMatch(filter);
            searcher.SizeLimit = sizeLimit;
            searcher.PageSize = 1000;
            searcher.Filter = filter;
            return searcher.FindOne();

        }
    }
}
