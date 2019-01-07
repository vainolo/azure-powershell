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
    /// The base class that defines the core properties of an auditing policy
    /// </summary>
    public class DatabaseStorageAuditingSettingsModel : DatabaseAuditingSettingsModel
    {
        /// <summary>
        /// Gets or sets the storage account name
        /// </summary>
        public string StorageAccountName { get; set; }

        /// <summary>
        /// Gets or sets the storage key type
        /// </summary>
        public StorageKeyKind StorageKeyType { get; set; }

        /// <summary>
        /// Gets or sets the retention days
        /// </summary>
        public uint? RetentionInDays { get; internal set; }

        /// <summary>
        /// Gets or sets the id of the storage account subscription.
        /// </summary>
        public Guid StorageAccountSubscriptionId { get; set; }
    }
}
