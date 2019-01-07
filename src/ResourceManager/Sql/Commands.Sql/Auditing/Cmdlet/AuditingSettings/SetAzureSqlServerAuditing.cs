// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using Microsoft.Azure.Commands.Common.Authentication.Abstractions;
using Microsoft.Azure.Commands.Sql.Auditing.Model;
using Microsoft.Azure.Commands.Sql.Common;
using System;
using System.Management.Automation;

namespace Microsoft.Azure.Commands.Sql.Auditing.Cmdlet.AuditingSettings
{
    /// <summary>
    /// Sets the auditing settings properties for a specific database server.
    /// </summary>
    [Cmdlet(
        VerbsCommon.Set,
        ResourceManager.Common.AzureRMConstants.AzureRMPrefix + "SqlServerAuditing",
        SupportsShouldProcess = true),
        OutputType(typeof(ServerAuditingSettingsModel))]
    public class SetAzureSqlServerAuditing : SqlServerAuditingSettingsCmdletBase
    {
        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.StateHelpMessage)]
        [ValidateSet(
            SecurityConstants.Enabled,
            SecurityConstants.Disabled,
            IgnoreCase = false)]
        public string State { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.BlobStorageParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.AuditActionGroupsHelpMessage)]
        [Parameter(
            ParameterSetName = DefinitionsCommon.EnableStorageAccountSubscriptionIdSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.AuditActionGroupsHelpMessage)]
        [Parameter(
            ParameterSetName = DefinitionsCommon.EventHubParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.AuditActionGroupsHelpMessage)]
        [Parameter(
            ParameterSetName = DefinitionsCommon.LogAnalyticsParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.AuditActionGroupsHelpMessage)]
        public AuditActionGroups[] AuditActionGroup { get; set; }

        [Parameter(
            Mandatory = false,
            HelpMessage = AuditingHelpMessages.PassThruHelpMessage)]
        public SwitchParameter PassThru { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.BlobStorageParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.PredicateExpressionHelpMessage)]
        [Parameter(
            ParameterSetName = DefinitionsCommon.EnableStorageAccountSubscriptionIdSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.PredicateExpressionHelpMessage)]
        [Parameter(
            ParameterSetName = DefinitionsCommon.EventHubParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.PredicateExpressionHelpMessage)]
        [Parameter(
            ParameterSetName = DefinitionsCommon.LogAnalyticsParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.PredicateExpressionHelpMessage)]
        [ValidateNotNull]
        public string PredicateExpression { get; internal set; }

        [Parameter(
            Mandatory = false,
            HelpMessage = AuditingHelpMessages.AsJobHelpMessage)]
        public SwitchParameter AsJob { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.BlobStorageParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.BlobStorageHelpMessage)]
        [Parameter(
            ParameterSetName = DefinitionsCommon.EnableStorageAccountSubscriptionIdSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.BlobStorageHelpMessage)]
        public override SwitchParameter BlobStorage { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.BlobStorageParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.AuditStorageAccountNameHelpMessage)]
        [Parameter(
            ParameterSetName = DefinitionsCommon.EnableStorageAccountSubscriptionIdSetName,
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.AuditStorageAccountNameHelpMessage)]
        [ValidateNotNullOrEmpty]
        public string StorageAccountName { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.EnableStorageAccountSubscriptionIdSetName,
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.AuditStorageAccountSubscriptionIdHelpMessage)]
        [ValidateNotNullOrEmpty]
        public Guid StorageAccountSubscriptionId { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.BlobStorageParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.StorageKeyTypeHelpMessage)]
        [Parameter(
            ParameterSetName = DefinitionsCommon.EnableStorageAccountSubscriptionIdSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.StorageKeyTypeHelpMessage)]
        [ValidateSet(
            SecurityConstants.Primary,
            SecurityConstants.Secondary,
            IgnoreCase = false)]
        public string StorageKeyType { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.BlobStorageParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.RetentionInDaysHelpMessage)]
        [Parameter(
            ParameterSetName = DefinitionsCommon.EnableStorageAccountSubscriptionIdSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.RetentionInDaysHelpMessage)]
        [ValidateNotNullOrEmpty]
        public uint? RetentionInDays { get; internal set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.EventHubParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.EventHubNameHelpMessage)]
        [ValidateNotNullOrEmpty]
        public string EventHubName { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.EventHubParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.EventHubAuthorizationRuleIdHelpMessage)]
        [ValidateNotNullOrEmpty]
        public string EventHubAuthorizationRuleId { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.LogAnalyticsParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.WorkspaceIdHelpMessage)]
        [ValidateNotNullOrEmpty]
        public string WorkspaceId { get; set; }

        /// <summary>
        /// Returns true if the model object that was constructed by this cmdlet should be written out
        /// </summary>
        /// <returns>True if the model object should be written out, False otherwise</returns>
        protected override bool WriteResult() { return PassThru; }

        /// <summary>
        /// Updates the given model element with the cmdlet specific operation 
        /// </summary>
        /// <param name="model">A model object</param>
        protected override ServerAuditingSettingsModel ApplyUserInputToModel(ServerAuditingSettingsModel model)
        {
            base.ApplyUserInputToModel(model);
            model.AuditState = State == SecurityConstants.Enabled ? AuditState.Enabled : AuditState.Disabled;

            if (AuditActionGroup != null && AuditActionGroup.Length != 0)
            {
                model.AuditActionGroup = AuditActionGroup;
            }

            if (PredicateExpression != null)
            {
                model.PredicateExpression = PredicateExpression = PredicateExpression;
            }

            if (ParameterSetName == DefinitionsCommon.BlobStorageParameterSetName ||
                ParameterSetName == DefinitionsCommon.EnableStorageAccountSubscriptionIdSetName)
            {
                ServerStorageAuditingSettingsModel storageModel = model as ServerStorageAuditingSettingsModel;
                if (RetentionInDays != null)
                {
                    storageModel.RetentionInDays = RetentionInDays;
                }

                if (StorageAccountName != null)
                {
                    storageModel.StorageAccountName = StorageAccountName;
                }

                if (MyInvocation.BoundParameters.ContainsKey(SecurityConstants.StorageKeyType)) // the user enter a key type - we use it (and running over the previously defined key type)
                {
                    storageModel.StorageKeyType = (StorageKeyType == SecurityConstants.Primary) ? StorageKeyKind.Primary : StorageKeyKind.Secondary;
                }

                if (!StorageAccountSubscriptionId.Equals(Guid.Empty))
                {
                    storageModel.StorageAccountSubscriptionId = StorageAccountSubscriptionId;
                }
                else if (StorageAccountName != null)
                {
                    storageModel.StorageAccountSubscriptionId = Guid.Parse(DefaultProfile.DefaultContext.Subscription.Id);
                }
            }

            return model;
        }

        /// <summary>
        /// This method is responsible to call the right API in the communication layer that will eventually send the information in the 
        /// object to the REST endpoint
        /// </summary>
        /// <param name="baseModel">The model object with the data to be sent to the REST endpoints</param>
        protected override ServerAuditingSettingsModel PersistChanges(ServerAuditingSettingsModel baseModel)
        {
            if (ParameterSetName == DefinitionsCommon.BlobStorageParameterSetName ||
                ParameterSetName == DefinitionsCommon.EnableStorageAccountSubscriptionIdSetName)
            {
                ModelAdapter.SetServerStorageAuditingPolicy(baseModel as ServerStorageAuditingSettingsModel, DefaultContext.Environment.GetEndpoint(AzureEnvironment.Endpoint.StorageEndpointSuffix));
            }

            return null;
        }
    }
}
