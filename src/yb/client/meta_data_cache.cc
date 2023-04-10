// Copyright (c) YugaByte, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.  You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.  See the License for the specific language governing permissions and limitations
// under the License.
//

#include "yb/client/meta_data_cache.h"

#include "yb/client/client.h"
#include "yb/client/permissions.h"
#include "yb/client/table.h"
#include "yb/client/yb_table_name.h"

#include "yb/common/roles_permissions.h"

#include "yb/util/result.h"
#include "yb/util/scope_exit.h"
#include "yb/util/status_format.h"
#include "yb/util/status_log.h"
#include "yb/util/flags.h"

using std::string;

DEFINE_UNKNOWN_int32(update_permissions_cache_msecs, 2000,
             "How often the roles' permissions cache should be updated. 0 means never update it");

namespace yb {
namespace client {

namespace {

Status GenerateUnauthorizedError(const std::string& canonical_resource,
                                 const ql::ObjectType& object_type,
                                 const RoleName& role_name,
                                 const PermissionType& permission,
                                 const NamespaceName& keyspace,
                                 const TableName& table) {
  switch (object_type) {
    case ql::ObjectType::TABLE:
      return STATUS_SUBSTITUTE(NotAuthorized,
          "User $0 has no $1 permission on <table $2.$3> or any of its parents",
          role_name, PermissionName(permission), keyspace, table);
    case ql::ObjectType::SCHEMA:
      if (canonical_resource == "data") {
        return STATUS_SUBSTITUTE(NotAuthorized,
            "User $0 has no $1 permission on <all keyspaces> or any of its parents",
            role_name, PermissionName(permission));
      }
      return STATUS_SUBSTITUTE(NotAuthorized,
          "User $0 has no $1 permission on <keyspace $2> or any of its parents",
          role_name, PermissionName(permission), keyspace);
    case ql::ObjectType::ROLE:
      if (canonical_resource == "role") {
        return STATUS_SUBSTITUTE(NotAuthorized,
            "User $0 has no $1 permission on <all roles> or any of its parents",
            role_name, PermissionName(permission));
      }
      return STATUS_SUBSTITUTE(NotAuthorized,
          "User $0 does not have sufficient privileges to perform the requested operation",
          role_name);
    default:
      return STATUS_SUBSTITUTE(IllegalState, "Unable to find permissions for object $0",
                               to_underlying(object_type));
  }
}

} // namespace

YBMetaDataCache::YBMetaDataCache(client::YBClient* client,
                                 bool create_roles_permissions_cache) : client_(client)  {
  if (create_roles_permissions_cache) {
    permissions_cache_ = std::make_shared<client::internal::PermissionsCache>(client);
  } else {
    LOG(INFO) << "Creating a metadata cache without a permissions cache";
  }
}

YBMetaDataCache::~YBMetaDataCache() = default;

Status YBMetaDataCache::GetTable(const YBTableName& table_name,
                                 std::shared_ptr<YBTable>* table,
                                 bool* cache_used) {
  std::shared_ptr<YBMetaDataCacheEntry> entry;
  {
    std::lock_guard<std::mutex> lock(cached_tables_mutex_);
    entry = GetOrCreateEntryInCacheUnlocked(&cached_tables_by_name_, table_name, table, cache_used);
    if (cache_used && *cache_used) {
      return Status::OK();
    }
  }

  return FetchTableDetailsInCache(entry, table_name, table, cache_used);
}

Status YBMetaDataCache::GetTable(const TableId& table_id,
                                 std::shared_ptr<YBTable>* table,
                                 bool* cache_used) {
  std::shared_ptr<YBMetaDataCacheEntry> entry;
  {
    std::lock_guard<std::mutex> lock(cached_tables_mutex_);
    entry = GetOrCreateEntryInCacheUnlocked(&cached_tables_by_id_, table_id, table, cache_used);
    if (cache_used && *cache_used) {
      return Status::OK();
    }
  }

  return FetchTableDetailsInCache(entry, table_id, table, cache_used);
}

template <typename T>
std::shared_ptr<YBMetaDataCacheEntry> YBMetaDataCache::GetOrCreateEntryInCacheUnlocked(
    std::unordered_map<T, std::shared_ptr<YBMetaDataCacheEntry>, boost::hash<T>>* cache,
    const T& table_identifier,
    std::shared_ptr<YBTable>* table,
    bool* cache_used) {
  auto itr = cache->find(table_identifier);
  if (itr != cache->end() && itr->second->fetched_successfully_.load(std::memory_order_acquire)) {
    *table = itr->second->table_;
    *cache_used = true;
    return itr->second;
  } else if (itr == cache->end()) {
    (*cache)[table_identifier] = std::make_shared<YBMetaDataCacheEntry>();
  }
  return (*cache)[table_identifier];
}

template <typename T>
Status YBMetaDataCache::FetchTableDetailsInCache(const std::shared_ptr<YBMetaDataCacheEntry> entry,
                                                 const T table_identifier,
                                                 std::shared_ptr<YBTable>* table,
                                                 bool* cache_used) {
  LOG_IF(DFATAL, entry == nullptr) << "YBMetaDataCacheEntry found to be null unexpectedly";

  {
    // Avoid multiple threads fetching the table details.
    std::unique_lock<std::mutex> table_lock(entry->m_);

    if (entry->fetching_.load(std::memory_order_acquire)) {
      // Another thread is already fetching the table info. Wait for it to finish.
      entry->fetch_wait_cv_.wait(
          table_lock, [&entry]() { return !entry->fetching_.load(std::memory_order_acquire); });
    } else if (!entry->fetched_successfully_.load(std::memory_order_acquire)) {
      entry->fetching_.store(true, std::memory_order_release);
    }
  }

  // Recheck the entry since another thread might have fetched and populated the entry.
  if (entry->fetched_successfully_.load(std::memory_order_acquire)) {
    *table = entry->table_;
    *cache_used = true;
    return Status::OK();
  }

  bool success = false;
  auto scope_exit = ScopeExit([&entry, &success] {
    if (!success) {
      entry->fetched_successfully_.store(false, std::memory_order_release);
      entry->fetching_.store(false, std::memory_order_release);
      entry->fetch_wait_cv_.notify_one();
    }
  });

  RETURN_NOT_OK(client_->OpenTable(table_identifier, table));

  // Notify as soon as possible in case of success.
  entry->table_ = *table;
  entry->fetched_successfully_.store(true, std::memory_order_release);
  entry->fetching_.store(false, std::memory_order_release);
  entry->fetch_wait_cv_.notify_all();
  success = true;

  {
    std::lock_guard<std::mutex> lock(cached_tables_mutex_);

    cached_tables_by_name_[(*table)->name()] = entry;
    cached_tables_by_id_[(*table)->id()] = entry;
  }
  *cache_used = false;
  return Status::OK();
}

void YBMetaDataCache::RemoveCachedTable(const YBTableName& table_name) {
  std::lock_guard<std::mutex> lock(cached_tables_mutex_);
  const auto itr = cached_tables_by_name_.find(table_name);
  if (itr != cached_tables_by_name_.end()) {
    // It could happen that the entry is present in cached_tables_by_name_ but the data is being
    // fetched. In this case, cached_tables_by_id_ might not have the entry.
    if (itr->second->fetched_successfully_.load(std::memory_order_acquire)) {
      const auto table_id = itr->second->table_->id();
      if (cached_tables_by_id_.contains(table_id)) {
        cached_tables_by_id_.erase(table_id);
      }
    }

    cached_tables_by_name_.erase(itr);
  }
}

void YBMetaDataCache::RemoveCachedTable(const TableId& table_id) {
  std::lock_guard<std::mutex> lock(cached_tables_mutex_);
  const auto itr = cached_tables_by_id_.find(table_id);
  if (itr != cached_tables_by_id_.end()) {
    // It could happen that the entry is present in cached_tables_by_id_ but the data is being
    // fetched. In this case, cached_tables_by_name_ might not have the entry.
    if (itr->second->fetched_successfully_.load(std::memory_order_acquire)) {
      const auto table_name = itr->second->table_->name();
      if (cached_tables_by_name_.contains(table_name)) {
        cached_tables_by_name_.erase(table_name);
      }
    }

    cached_tables_by_id_.erase(itr);
  }
}

Result<std::pair<std::shared_ptr<QLType>, bool>> YBMetaDataCache::GetUDType(
    const string& keyspace_name, const string& type_name) {
  auto type_path = std::make_pair(keyspace_name, type_name);
  {
    std::lock_guard<std::mutex> lock(cached_types_mutex_);
    auto itr = cached_types_.find(type_path);
    if (itr != cached_types_.end()) {
      return std::make_pair(itr->second, true);
    }
  }

  auto type = VERIFY_RESULT(client_->GetUDType(keyspace_name, type_name));
  {
    std::lock_guard<std::mutex> lock(cached_types_mutex_);
    cached_types_[type_path] = type;
  }
  return std::make_pair(std::move(type), false);
}

void YBMetaDataCache::RemoveCachedUDType(const string& keyspace_name,
                                         const string& type_name) {
  std::lock_guard<std::mutex> lock(cached_types_mutex_);
  cached_types_.erase(std::make_pair(keyspace_name, type_name));
}

Status YBMetaDataCache::WaitForPermissionCache() {
  if (!permissions_cache_) {
    LOG(WARNING) << "Permissions cache disabled. This only should be used in unit tests";
    return STATUS(TimedOut, "Permissions cache unavailable");
  }

  if (!permissions_cache_->ready()) {
    if (!permissions_cache_->WaitUntilReady(
            MonoDelta::FromMilliseconds(FLAGS_update_permissions_cache_msecs))) {
      return STATUS(TimedOut, "Permissions cache unavailable");
    }
  }
  return Status::OK();
}

Result<std::string> YBMetaDataCache::RoleSaltedHash(const RoleName& role_name) {
  RETURN_NOT_OK(WaitForPermissionCache());
  return permissions_cache_->salted_hash(role_name);
}

Result<bool> YBMetaDataCache::RoleCanLogin(const RoleName& role_name) {
  RETURN_NOT_OK(WaitForPermissionCache());
  return permissions_cache_->can_login(role_name);
}

Status YBMetaDataCache::HasResourcePermission(const std::string& canonical_resource,
                                              const ql::ObjectType& object_type,
                                              const RoleName& role_name,
                                              const PermissionType& permission,
                                              const NamespaceName& keyspace,
                                              const TableName& table,
                                              const CacheCheckMode check_mode) {
  if (!permissions_cache_) {
    LOG(WARNING) << "Permissions cache disabled. This only should be used in unit tests";
    return Status::OK();
  }

  if (object_type != ql::ObjectType::SCHEMA &&
      object_type != ql::ObjectType::TABLE &&
      object_type != ql::ObjectType::ROLE) {
    DFATAL_OR_RETURN_NOT_OK(STATUS_SUBSTITUTE(InvalidArgument, "Invalid ObjectType $0",
                                              to_underlying(object_type)));
  }

  if (!permissions_cache_->ready()) {
    if (!permissions_cache_->WaitUntilReady(
            MonoDelta::FromMilliseconds(FLAGS_update_permissions_cache_msecs))) {
      return STATUS(TimedOut, "Permissions cache unavailable");
    }
  }

  if (!permissions_cache_->HasCanonicalResourcePermission(canonical_resource, object_type,
                                                          role_name, permission)) {
    if (check_mode == CacheCheckMode::RETRY) {
      // We could have failed to find the permission because our cache is stale. If we are asked
      // to retry, we update the cache and try again.
      RETURN_NOT_OK(client_->GetPermissions(permissions_cache_.get()));
      if (permissions_cache_->HasCanonicalResourcePermission(canonical_resource, object_type,
                                                             role_name, permission)) {
        return Status::OK();
      }
    }
    return GenerateUnauthorizedError(
        canonical_resource, object_type, role_name, permission, keyspace, table);
  }

  // Found.
  return Status::OK();
}

Status YBMetaDataCache::HasTablePermission(const NamespaceName& keyspace_name,
                                           const TableName& table_name,
                                           const RoleName& role_name,
                                           const PermissionType permission,
                                           const CacheCheckMode check_mode) {

  // Check wihtout retry. In case our cache is stale, we will check again by issuing a recursive
  // call to this method.
  if (HasResourcePermission(get_canonical_keyspace(keyspace_name),
                            ql::ObjectType::SCHEMA, role_name, permission,
                            keyspace_name, "", CacheCheckMode::NO_RETRY).ok()) {
    return Status::OK();
  }

  // By default the first call asks to retry. If we decide to retry, we will issue a recursive
  // call with NO_RETRY mode.
  Status s = HasResourcePermission(get_canonical_table(keyspace_name, table_name),
                                   ql::ObjectType::TABLE, role_name, permission,
                                   keyspace_name, table_name,
                                   check_mode);

  if (check_mode == CacheCheckMode::RETRY && s.IsNotAuthorized()) {
    s = HasTablePermission(keyspace_name, table_name, role_name, permission,
                           CacheCheckMode::NO_RETRY);
  }
  return s;
}

} // namespace client
} // namespace yb
