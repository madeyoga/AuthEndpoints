namespace AuthEndpoints.External.OAuth;

public interface IExternalAuthProvider
{
    /// <summary>Authentication scheme name (e.g. <c>GitHub</c>, <c>Google</c>).</summary>
    string Scheme { get; }

    /// <summary>Relative login path under the mapped group (e.g. <c>login/github</c>).</summary>
    string LoginPath { get; }

    /// <summary>Relative callback path under the mapped group (e.g. <c>login/github/callback</c>).</summary>
    string CallbackPath { get; }

    /// <summary>Unique endpoint name for <see cref="Microsoft.AspNetCore.Routing.LinkGenerator"/>.</summary>
    string CallbackEndpointName { get; }
}
