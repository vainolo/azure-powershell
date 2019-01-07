namespace Microsoft.Azure.Commands.Sql.Auditing.Cmdlet.AuditingSettings
{
    public enum AuditTarget { BlobStorage, EventHub, LogAnalytics };

    public static class DefinitionsCommon
    {
        public const string BlobStorageParameterSetName = "BlobStorageSet";
        public const string EventHubParameterSetName = "EventHubSet";
        public const string LogAnalyticsParameterSetName = "LogAnalyticsSet";
        public const string EnableStorageAccountSubscriptionIdSetName = "StorageAccountSubscriptionIdSet";
    }
}
