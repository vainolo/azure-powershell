namespace Microsoft.Azure.Commands.Sql.Auditing.Model
{
    public class ServerEventHubAuditingSettingsModel : ServerAuditingSettingsModel
    {
        public string EventHubName { get; set; }

        public string EventHubAuthorizationRuleId { get; set; }
    }
}
