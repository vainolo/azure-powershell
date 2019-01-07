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
using Microsoft.Azure.Commands.Sql.Database.Services;
using Microsoft.Azure.Management.Sql.Models;
using Microsoft.WindowsAzure.Commands.Utilities.Common;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Azure.Commands.Sql.Auditing.Services
{
    /// <summary>
    /// The SqlAuditClient class is responsible for transforming the data that was received form the endpoints to the cmdlets model of auditing policy and vice versa
    /// </summary>
    public class SqlAuditAdapter
    {
        /// <summary>
        /// Gets or sets the Azure subscription
        /// </summary>
        private IAzureSubscription Subscription { get; set; }

        /// <summary>
        /// The auditing endpoints communicator used by this adapter
        /// </summary>
        private AuditingEndpointsCommunicator Communicator { get; set; }

        /// <summary>
        /// The Azure endpoints communicator used by this adapter
        /// </summary>
        private AzureEndpointsCommunicator AzureCommunicator { get; set; }

        /// <summary>
        /// Caching the fetched storage account name to prevent costly network interaction in cases it is not needed
        /// </summary>
        private string FetchedStorageAccountName { get; set; }

        /// <summary>
        /// Caching the fetched storage account subscription to prevent costly network interaction in cases it is not needed
        /// </summary>
        private string FetchedStorageAccountSubscription { get; set; }

        /// <summary>
        /// In cases when storage is not needed and not provided, there's no need to perform storage related network interaction that may fail
        /// </summary>
        public bool IgnoreStorage { get; set; }

        /// <summary>
        /// Gets or sets the Azure profile
        /// </summary>
        public IAzureContext Context { get; set; }

        public SqlAuditAdapter(IAzureContext context)
        {
            Context = context;
            Subscription = context.Subscription;
            Communicator = new AuditingEndpointsCommunicator(Context);
            AzureCommunicator = new AzureEndpointsCommunicator(Context);
            IgnoreStorage = false;
        }

        /// <summary>
        /// Provides a database audit policy model for the given database
        /// </summary>
        internal void GetDatabaseStorageAuditingSettingsModel(string resourceGroup, string serverName, string databaseName, DatabaseStorageAuditingSettingsModel model)
        {
            ExtendedDatabaseBlobAuditingPolicy policy;
            Communicator.GetExtendedDatabaseAuditingPolicy(resourceGroup, serverName, databaseName, out policy);
            ModelizeDatabaseStorageAuditPolicy(policy, model);
        }

        /// <summary>
        /// Provides a database server audit policy model for the given database
        /// </summary>
        internal void GetServerStorageAuditingPolicy(string resourceGroup, string serverName, ServerStorageAuditingSettingsModel model)
        {
            ExtendedServerBlobAuditingPolicy policy;
            Communicator.GetExtendedServerAuditingPolicy(resourceGroup, serverName, out policy);
            ModelizeServerStorageAuditPolicy(policy, model);
        }

        private void ModelizeDatabaseStorageAuditPolicy(ExtendedDatabaseBlobAuditingPolicy policy, DatabaseStorageAuditingSettingsModel model)
        {
            model.AuditState = policy.State == BlobAuditingPolicyState.Enabled ?
                AuditState.Enabled : AuditState.Disabled;
            ModelizeStorageInfo(model, policy.StorageEndpoint, policy.IsStorageSecondaryKeyInUse, policy.StorageAccountSubscriptionId);
            ModelizeAuditActionGroups(model, policy.AuditActionsAndGroups);
            ModelizeAuditActions(model, policy.AuditActionsAndGroups);
            ModelizeRetentionInfo(model, policy.RetentionDays);
            model.PredicateExpression = policy.PredicateExpression;
        }

        private void ModelizeAuditActionGroups(dynamic model, IEnumerable<string> auditActionsAndGroups)
        {
            var groups = new List<AuditActionGroups>();
            if (auditActionsAndGroups != null)
            {
                auditActionsAndGroups.ForEach(item =>
                {
                    AuditActionGroups group;
                    if (Enum.TryParse(item, true, out group))
                    {
                        groups.Add(group);
                    }
                });
            }

            model.AuditActionGroup = groups.ToArray();
        }

        private void ModelizeAuditActions(DatabaseAuditingSettingsModel model, IEnumerable<string> auditActionsAndGroups)
        {
            var actions = new List<string>();
            if (auditActionsAndGroups != null)
            {
                auditActionsAndGroups.ForEach(item =>
                {
                    AuditActionGroups group;
                    if (!Enum.TryParse(item, true, out group))
                    {
                        actions.Add(item);
                    }
                });
            }

            model.AuditAction = actions.ToArray();
        }

        private void ModelizeRetentionInfo(dynamic model, int? retentionDays)
        {
            model.RetentionInDays = Convert.ToUInt32(retentionDays);
        }

        private static void ModelizeStorageInfo(dynamic model, string storageEndpoint, bool? isSecondary, Guid? storageAccountSubscriptionId)
        {
            if (string.IsNullOrEmpty(storageEndpoint))
            {
                return;
            }
            var accountNameStartIndex = storageEndpoint.StartsWith("https://", StringComparison.InvariantCultureIgnoreCase) ? 8 : 7; // https:// or http://
            var accountNameEndIndex = storageEndpoint.IndexOf(".blob", StringComparison.InvariantCultureIgnoreCase);
            model.StorageAccountName = storageEndpoint.Substring(accountNameStartIndex, accountNameEndIndex - accountNameStartIndex);
            model.StorageKeyType = (isSecondary ?? false) ? StorageKeyKind.Secondary : StorageKeyKind.Primary;
            model.StorageAccountSubscriptionId = storageAccountSubscriptionId ?? Guid.Empty;
        }

        /// <summary>
        /// Transforms the given server policy object to its cmdlet model representation
        /// </summary>
        private void ModelizeServerStorageAuditPolicy(ExtendedServerBlobAuditingPolicy policy, ServerStorageAuditingSettingsModel serverStorageModel)
        {
            serverStorageModel.AuditState = policy.State == BlobAuditingPolicyState.Enabled ?
                AuditState.Enabled : AuditState.Disabled;
            
            ModelizeStorageInfo(serverStorageModel, policy.StorageEndpoint, policy.IsStorageSecondaryKeyInUse, policy.StorageAccountSubscriptionId);
            ModelizeAuditActionGroups(serverStorageModel, policy.AuditActionsAndGroups);
            ModelizeRetentionInfo(serverStorageModel, policy.RetentionDays);
            serverStorageModel.PredicateExpression = policy.PredicateExpression;
        }

        /// <summary>
        /// Transforms the given model to its endpoints acceptable structure and sends it to the endpoint
        /// </summary>
        public void SetDatabaseStorageAuditingPolicy(DatabaseAuditingSettingsModel model, string storageEndpointSuffix)
        {
            if (!IsDatabaseInServiceTierForPolicy(model.ResourceGroupName, model.ServerName, model.DatabaseName))
            {
                throw new Exception(Properties.Resources.DatabaseNotInServiceTierForAuditingPolicy);
            }

            if (string.IsNullOrEmpty(model.PredicateExpression))
            {
                var policy = new Management.Sql.Models.DatabaseBlobAuditingPolicy();
                PolicizeStorageAuditingModel(model, storageEndpointSuffix, policy);
                Communicator.SetDatabaseAuditingPolicy(model.ResourceGroupName, model.ServerName, model.DatabaseName, policy);
            }
            else
            {
                var policy = new Management.Sql.Models.ExtendedDatabaseBlobAuditingPolicy
                {
                    PredicateExpression = model.PredicateExpression
                };
                PolicizeStorageAuditingModel(model, storageEndpointSuffix, policy);
                Communicator.SetExtendedDatabaseAuditingPolicy(model.ResourceGroupName, model.ServerName, model.DatabaseName, policy);
            }
        }

        /// <summary>
        /// Transforms the given model to its endpoints acceptable structure and sends it to the endpoint
        /// </summary>
        public void SetServerStorageAuditingPolicy(ServerStorageAuditingSettingsModel model, string storageEndpointSuffix)
        {
            if (string.IsNullOrEmpty(model.PredicateExpression))
            {
                var policy = new ServerBlobAuditingPolicy();
                PolicizeStorageAuditingModel(model, storageEndpointSuffix, policy);
                Communicator.SetServerAuditingPolicy(model.ResourceGroupName, model.ServerName, policy);
            }
            else
            {
                var policy = new ExtendedServerBlobAuditingPolicy
                {
                    PredicateExpression = model.PredicateExpression
                };
                PolicizeStorageAuditingModel(model, storageEndpointSuffix, policy);
                Communicator.SetExtendedServerAuditingPolicy(model.ResourceGroupName, model.ServerName, policy);
            }
        }

        private bool IsDatabaseInServiceTierForPolicy(string resourceGroupName, string serverName, string databaseName)
        {
            var dbCommunicator = new AzureSqlDatabaseCommunicator(Context);
            var database = dbCommunicator.Get(resourceGroupName, serverName, databaseName);
            Database.Model.DatabaseEdition edition;
            Enum.TryParse(database.Edition, true, out edition);
            return edition != Database.Model.DatabaseEdition.None &&
                edition != Database.Model.DatabaseEdition.Free;
        }

        /// <summary>
        /// Takes the cmdlets model object and transform it to the policy as expected by the endpoint
        /// </summary>
        /// <param name="model">The AuditingPolicy model object</param>
        /// <param name="storageEndpointSuffix">The suffix of the storage endpoint</param>
        /// <param name="policy">The policy to be modified</param>
        /// <returns>The communication model object</returns>
        private void PolicizeStorageAuditingModel(dynamic model, string storageEndpointSuffix, dynamic policy)
        {
            policy.State = model.AuditState == AuditState.Enabled ? 
                BlobAuditingPolicyState.Enabled : BlobAuditingPolicyState.Disabled;
            if (!IgnoreStorage && (model.AuditState == AuditState.Enabled))
            {
                policy.StorageEndpoint = ExtractStorageAccountName(model, storageEndpointSuffix);
                policy.StorageAccountAccessKey = Subscription.GetId().Equals(model.StorageAccountSubscriptionId) ?
                    ExtractStorageAccountKey(model.StorageAccountName, model.StorageKeyType) :
                    ExtractStorageAccountKey(model.StorageAccountSubscriptionId, model.StorageAccountName, model.StorageKeyType);
                policy.IsStorageSecondaryKeyInUse = model.StorageKeyType == StorageKeyKind.Secondary;
                policy.StorageAccountSubscriptionId = Subscription.GetId().Equals(model.StorageAccountSubscriptionId) ?
                    Guid.Parse(ExtractStorageAccountSubscriptionId(model.StorageAccountName)) : model.StorageAccountSubscriptionId;
            }
            policy.AuditActionsAndGroups = ExtractAuditActionsAndGroups(model);
            if (model.RetentionInDays != null)
            {
                policy.RetentionDays = (int)model.RetentionInDays;
            }
        }

        private static IList<string> ExtractAuditActionsAndGroups(dynamic model)
        {
            var actionsAndGroups = new List<string>();
            DatabaseStorageAuditingSettingsModel dbModel = model as DatabaseStorageAuditingSettingsModel;
            if (dbModel != null)
            {
                actionsAndGroups.AddRange(dbModel.AuditAction);
            }

            AuditActionGroups[] auditActionGroup = model.AuditActionGroup;
            auditActionGroup.ToList().ForEach(aag => actionsAndGroups.Add(aag.ToString()));
            if (actionsAndGroups.Count == 0) // default audit actions and groups in case nothing was defined by the user
            {
                actionsAndGroups.Add("SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP");
                actionsAndGroups.Add("FAILED_DATABASE_AUTHENTICATION_GROUP");
                actionsAndGroups.Add("BATCH_COMPLETED_GROUP");
            }
            return actionsAndGroups;
        }

        /// <summary>
        /// Extracts the storage account name from the given model
        /// </summary>
        private static string ExtractStorageAccountName(dynamic model, string endpointSuffix)
        {
            return string.Format("https://{0}.blob.{1}", model.StorageAccountName, endpointSuffix);
        }

        /// <summary>
        /// Extracts the storage account subscription id
        /// </summary>
        private string ExtractStorageAccountSubscriptionId(string storageName)
        {
            if (IgnoreStorage || (storageName == FetchedStorageAccountName && FetchedStorageAccountSubscription != null))
            {
                return FetchedStorageAccountSubscription;
            }
            return Subscription.Id.ToString();
        }

        private string ExtractStorageAccountKey(Guid storageAccountSubscriptionId, string storageAccountName, StorageKeyKind storageKeyKind)
        {
            return AzureCommunicator.RetrieveStorageKeys(storageAccountSubscriptionId, storageAccountName)[storageKeyKind];
        }

        /// <summary>
        /// Extracts the storage account requested key
        /// </summary>
        private string ExtractStorageAccountKey(string storageName, StorageKeyKind storageKeyKind)
        {
            return AzureCommunicator.GetStorageKeys(storageName)[storageKeyKind];
        }
    }
}
