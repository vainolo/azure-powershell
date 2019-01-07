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
using Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters;
using Microsoft.Azure.Commands.Sql.Auditing.Model;
using Microsoft.Azure.Commands.Sql.Auditing.Services;
using Microsoft.Azure.Commands.Sql.Common;
using System.Management.Automation;

namespace Microsoft.Azure.Commands.Sql.Auditing.Cmdlet.AuditingSettings
{
    /// <summary>
    /// The base class for Azure SQL server auditing settings Management Cmdlets
    /// </summary>
    public abstract class SqlServerAuditingSettingsCmdletBase : AzureSqlCmdletBase<ServerAuditingSettingsModel, SqlAuditAdapter>
    {
        /// <summary>
        /// Gets or sets the name of the SQL server to use.
        /// </summary>
        [Parameter(Mandatory = true, Position = 1, ValueFromPipelineByPropertyName = true, HelpMessage = "SQL server name.")]
        [ResourceNameCompleter("Microsoft.Sql/servers", "ResourceGroupName")]
        [ValidateNotNullOrEmpty]
        public string ServerName { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.BlobStorageParameterSetName,
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.BlobStorageHelpMessage)]
        public virtual SwitchParameter BlobStorage { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.EventHubParameterSetName,
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.EventHubHelpMessage)]
        public SwitchParameter EventHub { get; set; }

        [Parameter(
            ParameterSetName = DefinitionsCommon.LogAnalyticsParameterSetName,
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = AuditingHelpMessages.LogAnalyticsHelpMessage)]
        public SwitchParameter LogAnalytics { get; set; }

        /// <summary>
        /// Provides the model element that this cmdlet operates on
        /// </summary>
        /// <returns>A model object</returns>
        protected override ServerAuditingSettingsModel GetEntity()
        {
            ServerAuditingSettingsModel model = null;
            if (ParameterSetName == DefinitionsCommon.BlobStorageParameterSetName ||
                ParameterSetName == DefinitionsCommon.EnableStorageAccountSubscriptionIdSetName)
            {
                model = new ServerStorageAuditingSettingsModel();
                ModelAdapter.GetServerStorageAuditingPolicy(ResourceGroupName, ServerName, model as ServerStorageAuditingSettingsModel);
            }
            else if (ParameterSetName == DefinitionsCommon.EventHubParameterSetName)
            {
                model = new ServerEventHubAuditingSettingsModel();
            }
            else if (ParameterSetName == DefinitionsCommon.LogAnalyticsParameterSetName)
            {
                model = new ServerLogAnalyticsAuditingSettingsModel();
            }

            model.ResourceGroupName = ResourceGroupName;
            model.ServerName = ServerName;
            return model;
        }

        /// <summary>
        /// Creation and initialization of the ModelAdapter object
        /// </summary>
        /// <param name="subscription">The AzureSubscription in which the current execution is performed</param>
        /// <returns>An initialized and ready to use ModelAdapter object</returns>
        protected override SqlAuditAdapter InitModelAdapter(IAzureSubscription subscription)
        {
            return new SqlAuditAdapter(DefaultProfile.DefaultContext);
        }
    }
}
