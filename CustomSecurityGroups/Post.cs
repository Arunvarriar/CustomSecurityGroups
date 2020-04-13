using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace CustomSecurityGroups
{
    class Post
    {

        public string PostGroupEntitlements(string pat, string link, string postJson)
        {
            string responseBody = "";
            string Url = link;

            //HttpClient client = new HttpClient();

            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(
                        ASCIIEncoding.ASCII.GetBytes(
                        string.Format("{0}:{1}", "", pat))));

                var method = new HttpMethod("POST");
                var request = new HttpRequestMessage(method, Url)
                {
                    Content = new StringContent(postJson, Encoding.UTF8, "application/json")

                };
                using (HttpResponseMessage response = client.SendAsync(request).Result)
                {
                    response.EnsureSuccessStatusCode();
                    responseBody = response.Content.ReadAsStringAsync().Result;
                }
                return responseBody;

            }
        }
    }
}
