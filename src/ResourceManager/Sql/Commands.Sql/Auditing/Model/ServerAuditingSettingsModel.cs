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

using System;

namespace Microsoft.Azure.Commands.Sql.Auditing.Model
{
    /// <summary>
    /// The possible states in which an auditing policy may be in
    /// </summary>
    public enum AuditState { Enabled, Disabled };

    public enum AuditActionGroups
    {
        BATCH_STARTED_GROUP,
        BATCH_COMPLETED_GROUP,
        APPLICATION_ROLE_CHANGE_PASSWORD_GROUP,
        BACKUP_RESTORE_GROUP,
        DATABASE_LOGOUT_GROUP,
        DATABASE_OBJECT_CHANGE_GROUP,
        DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP,
        DATABASE_OBJECT_PERMISSION_CHANGE_GROUP,
        DATABASE_OPERATION_GROUP,
        DATABASE_PERMISSION_CHANGE_GROUP,
        DATABASE_PRINCIPAL_CHANGE_GROUP,
        DATABASE_PRINCIPAL_IMPERSONATION_GROUP,
        DATABASE_ROLE_MEMBER_CHANGE_GROUP,
        FAILED_DATABASE_AUTHENTICATION_GROUP,
        SCHEMA_OBJECT_ACCESS_GROUP,
        SCHEMA_OBJECT_CHANGE_GROUP,
        SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP,
        SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP,
        SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP,
        USER_CHANGE_PASSWORD_GROUP
    }

    /// <summary>
    /// types of storage keys
    /// </summary>
    public enum StorageKeyKind { Primary, Secondary };

    /// <summary>
    /// The base class that defines the core properties of an auditing policy
    /// </summary>
    public abstract class ServerAuditingSettingsModel
    {
        /// <summary>
        /// Gets or sets the resource group
        /// </summary>
        public string ResourceGroupName { get; set; }

        /// <summary>
        /// Gets or sets the server name
        /// </summary>
        public string ServerName { get; set; }

        /// <summary>
        /// Gets or sets the audit state
        /// </summary>
        public AuditState AuditState { get; set; }

        public AuditActionGroups[] AuditActionGroup { get; set; }

        /// <summary>
        /// Gets or sets predicate expression
        /// </summary>
        public string PredicateExpression { get; set; }

        internal const string DisabledOrGetAuditParameterSetName = "DisableAuditParameterSet";
        internal const string EnableBlobStorageParameterSetName = "BlobStorageParameterSet";
        internal const string EnableEventHubParameterSetName = "EventHubParameterSet";
        internal const string EnableLogAnalyticsParameterSetName = "WorkspaceIdParameterSet";
        internal const string EnableStorageAccountSubscriptionIdSetName = "StorageAccountSubscriptionIdSet";

    }
}
