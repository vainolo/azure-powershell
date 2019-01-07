namespace Microsoft.Azure.Commands.Sql.Auditing.Model
{
    public class DatabsaeEventHubAuditingSettingsModel : DatabaseAuditingSettingsModel
    {
        public string EventHubName { get; set; }

        public string EventHubAuthorizationRuleId { get; set; }
    }
}
