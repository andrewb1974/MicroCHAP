using System.Net;
#if !NET462
using System.Net.Http;
using System.Threading.Tasks;
#endif

namespace MicroCHAP.Client
{
	public abstract class ChapClientServiceBase
	{
		private readonly string _remoteBaseUrl;
		private readonly string _challengeUrl;
		private readonly ISignatureService _responseService;

		protected ChapClientServiceBase(string remoteBaseUrl, string challengeUrl, ISignatureService responseService)
		{
			_remoteBaseUrl = remoteBaseUrl;
			_challengeUrl = challengeUrl;
			_responseService = responseService;
		}

		protected virtual string ConvertUrlToAbsolute(string relativeUrl)
		{
			if (relativeUrl.StartsWith("http")) return relativeUrl;
			if (relativeUrl.StartsWith("~")) relativeUrl = relativeUrl.Substring(1);
			if (!relativeUrl.StartsWith("/")) relativeUrl = "/" + relativeUrl;

			return _remoteBaseUrl + relativeUrl;
		}

#if NET462
        protected virtual WebClient CreateAuthenticatedWebClient(string url, params SignatureFactor[] additionalFactors)
		{
			var challenge = GetChallenge();
			var client = new WebClient();

            client.Headers.Add("X-MC-MAC", _responseService.CreateSignature(challenge, url, additionalFactors));
            client.Headers.Add("X-MC-Nonce", challenge);

			return client;
		}

		protected virtual string GetChallenge()
		{
			var client = new WebClient();
            return client.DownloadString(_remoteBaseUrl + _challengeUrl);
		}
#else
        protected virtual HttpClient CreateAuthenticatedWebClient(string url, params SignatureFactor[] additionalFactors)
		{
			var challenge = GetChallenge();
			var client = new HttpClient();

            client.DefaultRequestHeaders.Add("X-MC-MAC", _responseService.CreateSignature(challenge, url, additionalFactors));
            client.DefaultRequestHeaders.Add("X-MC-Nonce", challenge);

			return client;
		}

		protected virtual string GetChallenge()
		{
			var client = new HttpClient();

            Task<string> task = client.GetStringAsync(_remoteBaseUrl + _challengeUrl);

            task.Wait();

            return task.Result;
		}
#endif
    }
}
