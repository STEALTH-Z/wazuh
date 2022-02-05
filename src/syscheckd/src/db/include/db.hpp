/*
 * Wazuh DB
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 12, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DB_HPP
#define _DB_HPP
#include "db.h"
#include <string.h>
#include <functional>
#include <json.hpp>

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

typedef enum COUNT_SELECT_TYPE {
    COUNT_ALL,
    COUNT_INODE,
} COUNT_SELECT_TYPE;

typedef enum FILE_SEARCH_TYPE {
    SEARCH_TYPE_PATH,
    SEARCH_TYPE_INODE
} FILE_SEARCH_TYPE;

using SearchData = std::tuple<FILE_SEARCH_TYPE, std::string, std::string, std::string>;

class EXPORTED DB final
{
public:
    static DB& instance()
    {
        static DB s_instance;
        return s_instance;
    }

    /**
    * @brief Init facade with database connection
    *
    * @param storage Storage type.
    * @param syncInterval Sync sync interval.
    * @param callbackSyncFileWrapper Callback sync file values.
    * @param callbackSyncRegistryWrapper Callback sync registry values.
    * @param callbackLogWrapper Callback to log lines.
    * @param fileLimit File limit.
    * @param valueLimit Registry value limit.
    * @param isWindows Enable Windows support.
    */
    void init(const int storage,
              const int syncInterval,
              std::function<void(const std::string&)> callbackSyncFileWrapper,
              std::function<void(const std::string&)> callbackSyncRegistryWrapper,
              std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
              int fileLimit,
              int valueLimit,
              bool isWindows);

    /**
    * @brief runIntegrity Execute the integrity mechanism.
    */
    void runIntegrity();

    /**
    * @brief pushMessage Push a message to the queue of the integrity mechanism.
    *
    * @param message Message payload comming from the manager.
    */
    void pushMessage(const std::string &message);

    /**
    * @brief DBSyncHandle return the dbsync handle, for operations with the database.
    *
    * @return dbsync handle.
    */
    DBSYNC_HANDLE DBSyncHandle();

    /**
    * @brief removeFile Remove a file from the database.
    *
    * @param path File to remove.
    */
    void removeFile(const std::string& path);

    /**
    * @brief getFile Get a file from the database.
    *
    * @param path File to get.
    * @param callback Callback return the file data.
    */
    void getFile(const std::string& path, std::function<void(const nlohmann::json&)> callback);

    /**
    * @brief countFiles Count files in the database.
    *
    * @param selectType Type of count.
    * @return Number of files.
    */
    int countFiles(const COUNT_SELECT_TYPE selectType);

    /**
    * @brief updateFile Update/insert a file in the database.
    *
    * @param file File entry/data to update/insert.
    * @return true if the file was updated, false if the file is inserted.
    */
    bool updateFile(const nlohmann::json &file);

    /**
    * @brief searchFiles Search files in the database.
    *
    * @param searchData parameter to search information.
    * @param callback Callback return the file data.
    */
    void searchFile(const SearchData& data, std::function<void(const std::string &)> callback);

    /**
    * @brief teardown Close the fimdb instances.
    */
    void teardown();

private:
    DB() = default;
    ~DB() = default;
    DB(const DB&) = delete;
    DB& operator=(const DB&) = delete;
    std::string CreateStatement(const bool isWindows);
};


#endif //_IFIMDB_HPP