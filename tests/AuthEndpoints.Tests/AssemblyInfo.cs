using Xunit;

// Identity/Passkey rate limits are IP-partitioned; parallel classes share one TestServer IP.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
