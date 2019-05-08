using System;
#if NET462
using System.Web;
#else
using Microsoft.AspNetCore.Http;
#endif

namespace MicroCHAP.Server
{
	/// <summary>
	/// Note: if using DI, this should be registered with singleton lifespan
	/// </summary>
	public interface IChapServer
	{
		string GetChallengeToken();
		bool ValidateToken(string challenge, string response, string url, params SignatureFactor[] additionalFactors);
		bool ValidateToken(string challenge, string response, string url, IChapServerLogger logger, params SignatureFactor[] additionalFactors);
#if NET462
        bool ValidateRequest(HttpRequestBase request);
		bool ValidateRequest(HttpRequestBase request, IChapServerLogger logger);
		bool ValidateRequest(HttpRequestBase request, Func<HttpRequestBase, SignatureFactor[]> factorParser);
		bool ValidateRequest(HttpRequestBase request, Func<HttpRequestBase, SignatureFactor[]> factorParser, IChapServerLogger logger);
#else
        bool ValidateRequest(HttpRequest request);
		bool ValidateRequest(HttpRequest request, IChapServerLogger logger);
		bool ValidateRequest(HttpRequest request, Func<HttpRequest, SignatureFactor[]> factorParser);
		bool ValidateRequest(HttpRequest request, Func<HttpRequest, SignatureFactor[]> factorParser, IChapServerLogger logger);
#endif
    }
}