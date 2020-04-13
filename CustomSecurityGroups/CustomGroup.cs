using System;
using System.Linq;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CustomSecurityGroups
{
    public static class CustomGroup
    {

        public static string accountName = Environment.GetEnvironmentVariable("AccountName");
        public static string pat = Environment.GetEnvironmentVariable("PAT");
        public static string groupName = "MyGroup";
        [FunctionName("CustomGroups")]
        public static void Run([TimerTrigger("0 */5 * * * *")]TimerInfo myTimer, ILogger log)
        {
            Get objGetApi = new Get();
            Post objPostapi = new Post();
            string projectsUrl;
            int projectAccesslevel = 1;
            //Below bits purely depends on you.
            int buildAccesslevel = 7919;
            int repoAccesslevel = 16502;
            int releaseAccesslevel = 3583;
            string listofProjects = objGetApi.getAdoAPI(pat, projectsUrl = string.Format(
        @"https://dev.azure.com/{0}/_apis/projects?$top=500&api-version=5.1",
          accountName));
            dynamic projectList = JsonConvert.DeserializeObject(listofProjects.ToString());
            int countProjects = projectList.count;
            string listofGroups = objGetApi.getAdoAPI(pat, projectsUrl = string.Format(
        @"https://vssps.dev.azure.com/{0}/_apis/graph/groups?api-version=5.1-preview.1",
         accountName));
            JObject objlistofProjects = JObject.Parse(listofProjects);
            var grouplistofProjects = objlistofProjects.SelectTokens("$..name").ToArray();
            var groupofprojectIds = objlistofProjects.SelectTokens("$..id").ToArray();
            JObject objlistofGroups = JObject.Parse(listofGroups);
            var totallistofGroups = objlistofGroups.SelectTokens("$..principalName").ToArray();           
            for (int i = 0; i < countProjects; i++)
            {
                var projectGroup = "[" + grouplistofProjects[i] + "]" + @"\" + groupName;
                if (!totallistofGroups.Contains(projectGroup))
                {
                    //storageKey is equivalent to project id
                    var storageKey = groupofprojectIds[i];
                    string getDescriptors = objGetApi.getAdoAPI(pat, projectsUrl = string.Format(
         @"https://vssps.dev.azure.com/{0}/_apis/graph/descriptors/" + storageKey + "?api-version=5.1-preview.1",
          accountName));
                    dynamic descrptorJson = JsonConvert.DeserializeObject(getDescriptors.ToString());
                    string scopeProject = descrptorJson.value;
                    string jsonGroup = GroupRefJson(groupName);
                    //scp.NjBkNGUyOTktMWJlMC00ZTIyLWIyZDItM2FlMTU4MjA2NmEx
                    string getGroupid=objPostapi.PostGroupEntitlements(pat, projectsUrl = string.Format(@"https://vssps.dev.azure.com/{0}/_apis/graph/groups?scopeDescriptor=" + scopeProject + "&api-version=5.1-preview.1", accountName), jsonGroup);
                    dynamic getOriginid = JsonConvert.DeserializeObject(getGroupid);
                    string descriptorId = getOriginid.descriptor;
                    string pDomain = getOriginid.domain;
                    string projectDomain= "$PROJECT:" + pDomain;
                    string seperator = "vssgp.";
                    string[] descriptorstring = descriptorId.Split(seperator);
                    string descriptor = descriptorstring[1];
                    string basedescriptor = Base64Decode(descriptor);
                    //Project Level Access
                    string jAccess = AccessControl(projectDomain, basedescriptor, projectAccesslevel);
                    log.LogInformation(jAccess);
                    //You can get namescpace id from namespaceid.json in this repo and for refer https://docs.microsoft.com/en-us/rest/api/azure/devops/security/security%20namespaces/query?view=azure-devops-rest-5.1
                    objPostapi.PostGroupEntitlements(pat, projectsUrl = string.Format(@"https://dev.azure.com/{0}/_apis/accesscontrolentries/52d39943-cb85-4d7f-8fa8-c6baac873819?api-version=5.1", accountName), jAccess);
                    //Build Level Access
                    jAccess = AccessControl(storageKey.ToString(), basedescriptor, buildAccesslevel);
                    objPostapi.PostGroupEntitlements(pat, projectsUrl = string.Format(@"https://dev.azure.com/{0}/_apis/accesscontrolentries/33344d9c-fc72-4d6f-aba5-fa317101a7e9?api-version=5.1", accountName), jAccess);
                    //Repo level Access
                    string repoToken= "repoV2/" + storageKey.ToString()+"/";
                    jAccess = AccessControl(repoToken, basedescriptor, repoAccesslevel);
                    objPostapi.PostGroupEntitlements(pat, projectsUrl = string.Format(@"https://dev.azure.com/{0}/_apis/accesscontrolentries/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87?api-version=5.1", accountName), jAccess);
                    //Release level Access
                    string relToken = storageKey.ToString() + "/1";
                    jAccess = AccessControl(relToken, basedescriptor, releaseAccesslevel);
                    objPostapi.PostGroupEntitlements(pat, projectsUrl = string.Format(@"https://dev.azure.com/{0}/_apis/accesscontrolentries/c788c23e-1b46-4162-8f5e-d7585343b5de?api-version=5.1", accountName), jAccess);
                    log.LogInformation($"C# Timer trigger function executed at: {DateTime.Now}");
                }
            }
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var lengthMod4 = base64EncodedData.Length % 4;
            if (lengthMod4 != 0)
            {
                //fix Invalid length for a Base-64 char array or string
                base64EncodedData += new string('=', 4 - lengthMod4);
            }
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }


        public static string GroupRefJson(string groupName)
        {
            return JsonConvert.SerializeObject(new
            {
                displayName = groupName,
                description = "Group at project level created via client library",

            });

        }
        public static string AccessControl(string token, string basedescriptor, int accessLevel)
        {
            string projectToken = token;
            string totalDescriptor = "Microsoft.TeamFoundation.Identity;" + basedescriptor;
            int jPermissionbit = accessLevel;
            bool jTrue = true;            
            return JsonConvert.SerializeObject(new
            {
                token = projectToken,
                merge = jTrue,
                accessControlEntries = new object[]
                {new{
                    descriptor = totalDescriptor,
                    allow= jPermissionbit,
                    deny=0,
                    extendedinfo =new object{},
                    }
                },

            });

        }

    }
}
