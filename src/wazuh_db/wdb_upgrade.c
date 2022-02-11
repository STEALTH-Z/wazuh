/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * December 12, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "wdb.h"

// This function performs those data migrations between
// updates that cannot be resolved with queries
static int wdb_adjust_upgrade(wdb_t *wdb, int upgrade_step);
static int wdb_adjust_global_upgrade(wdb_t *wdb, int upgrade_step);

// Migrate to the fourth version of the database:
// - The attributes field of the fim_entry table is decoded
static int wdb_adjust_v4(wdb_t *wdb);

/* SQL statements used for the global.db upgrade */
typedef enum wdb_stmt_global {
    WDB_STMT_GLOBAL_CHECK_MANAGER_KEEPALIVE,
} wdb_stmt_metadata;

static const char *SQL_GLOBAL_STMT[] = {
    "SELECT COUNT(*) FROM agent WHERE id=0 AND last_keepalive=253402300799;",
};

// Upgrade agent database to last version
wdb_t * wdb_upgrade(wdb_t *wdb) {
    const char * UPDATES[] = {
        schema_upgrade_v1_sql,
        schema_upgrade_v2_sql,
        schema_upgrade_v3_sql,
        schema_upgrade_v4_sql,
        schema_upgrade_v5_sql,
        schema_upgrade_v6_sql,
        schema_upgrade_v7_sql,
        schema_upgrade_v8_sql
    };

    char db_version[OS_SIZE_256 + 2];
    int version = 0;

    switch (wdb_metadata_get_entry(wdb, "db_version", db_version)) {
    case -1:
        return wdb;

    case 0:
        break;

    default:
        version = atoi(db_version);

        if (version < 0) {
            merror("DB(%s): Incorrect database version: %d", wdb->id, version);
            return wdb;
        }
    }

    for (unsigned i = version; i < sizeof(UPDATES) / sizeof(char *); i++) {
        mdebug2("Updating database '%s' to version %d", wdb->id, i + 1);

        if (wdb_sql_exec(wdb, UPDATES[i]) == -1 || wdb_adjust_upgrade(wdb, i)) {
            wdb = wdb_backup(wdb, version);
            break;
        }
    }

    return wdb;
}

wdb_t * wdb_upgrade_global(wdb_t *wdb) {
    const char * UPDATES[] = {
        schema_global_upgrade_v1_sql,
        schema_global_upgrade_v2_sql,
        schema_global_upgrade_v3_sql,
        schema_global_upgrade_v4_sql
    };

    char output[OS_MAXSTR + 1] = {0};
    char db_version[OS_SIZE_256 + 2];
    int version = 0;
    int updates_length = (int)(sizeof(UPDATES)/sizeof(char*));

    switch (wdb_metadata_table_check(wdb,"metadata")) {
    case OS_INVALID:
        /**
         * We can't determine if the database should be upgraded. If we allow the database
         * usage, we could have many errors because of an operation over an old database version.
         * If we recreate the database, we have the risk of loosing data of the newer database
         * versions. We should block the usage until determine whether we should upgrade or not.
         */
        merror("DB(%s) Error trying to find metadata table", wdb->id);
        wdb->enabled = false;
        return wdb;
    case OS_SUCCESS:
        /**
         * The table doesn't exist. Checking if version is 3.10 to upgrade. In case of
         * having a version lower than 3.10, we recreate the global.db database as we
         * can't upgrade and we will not lose critical data.
         */
        if (wdb_upgrade_check_manager_keepalive(wdb) != 1) {
            if (OS_SUCCESS != wdb_global_create_backup(wdb, output, "-pre_upgrade")) {
                merror("Creating pre-upgrade Global DB snapshot failed: %s", output);
                wdb->enabled = false;
            }
            else {
                wdb = wdb_recreate_global(wdb);
            }
            return wdb;
        }
        break;
    default:
        if (wdb_metadata_get_entry(wdb, "db_version", db_version) == 1) {
            version = atoi(db_version);
        }
        else {
            /**
             * We can't determine if the database should be upgraded. If we allow the usage,
             * we could have many errors because of an operation over an old database version.
             * We should block the usage until determine whether we should upgrade or not.
             */
            mwarn("DB(%s): Error trying to get DB version", wdb->id);
            wdb->enabled = false;
            return wdb;
        }
    }

    if (version < updates_length) {
        if (OS_SUCCESS != wdb_global_create_backup(wdb, output, "-pre_upgrade")) {
            merror("Creating pre-upgrade Global DB snapshot failed: %s", output);
            wdb->enabled = false;
        }
        else {
            for (int i = version; i < updates_length; i++) {
                mdebug2("Updating database '%s' to version %d", wdb->id, i + 1);
                if (wdb_sql_exec(wdb, UPDATES[i]) == OS_INVALID || wdb_adjust_global_upgrade(wdb, i)) {
                    char *bkp_name = NULL;
                    if (OS_INVALID != wdb_global_get_most_recent_backup(&bkp_name) &&
                        OS_INVALID != wdb_global_restore_backup(&wdb, bkp_name, false, output)) {
                        merror("Failed to update global.db to version %d. The global.db was restored to the original state.", i + 1);
                        wdb->enabled = true;
                    }
                    else if (bkp_name) {
                        merror("Failed to update global.db to version %d. The global.db should be restored from %s.", i + 1, bkp_name);
                        wdb->enabled = false;
                    }
                    else {
                        merror("Failed to update global.db to version %d.", i + 1);
                        wdb->enabled = false;
                    }
                    os_free(bkp_name);
                    break;
                }
            }
        }
    }

    return wdb;
}

// Create backup and generate an empty DB
wdb_t * wdb_backup(wdb_t *wdb, int version) {
    char path[PATH_MAX];
    char * sagent_id;
    wdb_t * new_wdb = NULL;
    sqlite3 * db;

    os_strdup(wdb->id, sagent_id),
    snprintf(path, PATH_MAX, "%s/%s.db", WDB2_DIR, sagent_id);

    if (wdb_close(wdb, TRUE) != -1) {
        if (wdb_create_backup(sagent_id, version) != -1) {
            mwarn("Creating DB backup and create clear DB for agent: '%s'", sagent_id);
            unlink(path);

            //Recreate DB
            if (wdb_create_agent_db2(sagent_id) < 0) {
                merror("Couldn't create SQLite database for agent '%s'", sagent_id);
                free(sagent_id);
                return NULL;
            }

            if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
                merror("Can't open SQLite backup database '%s': %s", path, sqlite3_errmsg(db));
                sqlite3_close_v2(db);
                free(sagent_id);
                return NULL;
            }

            new_wdb = wdb_init(db, sagent_id);
            wdb_pool_append(new_wdb);
        }
    } else {
        merror("Couldn't create SQLite database backup for agent '%s'", sagent_id);
    }

    free(sagent_id);
    return new_wdb;
}

wdb_t * wdb_recreate_global(wdb_t *wdb) {
    char path[PATH_MAX];
    wdb_t * new_wdb = NULL;
    sqlite3 * db;

    snprintf(path, PATH_MAX, "%s/%s.db", WDB2_DIR, WDB_GLOB_NAME);

    if (wdb_close(wdb, TRUE) != OS_INVALID) {
        unlink(path);

        if (OS_SUCCESS != wdb_create_global(path)) {
            merror("Couldn't create SQLite database '%s'", path);
            return NULL;
        }

        if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
            merror("Can't open SQLite backup database '%s': %s", path, sqlite3_errmsg(db));
            sqlite3_close_v2(db);
            return NULL;
        }

        new_wdb = wdb_init(db, WDB_GLOB_NAME);
        wdb_pool_append(new_wdb);
    }

    return new_wdb;
}

/* Create backup for agent. Returns 0 on success or -1 on error. */
int wdb_create_backup(const char * agent_id, int version) {
    char path[OS_FLSIZE + 1];
    char buffer[4096];
    FILE *source;
    FILE *dest;
    size_t nbytes;
    int result = 0;

    snprintf(path, OS_FLSIZE, "%s/%s.db", WDB2_DIR, agent_id);

    if (!(source = fopen(path, "r"))) {
        merror("Couldn't open source '%s': %s (%d)", path, strerror(errno), errno);
        return -1;
    }

    snprintf(path, OS_FLSIZE, "%s/%s.db-oldv%d-%lu", WDB2_DIR, agent_id, version, (unsigned long)time(NULL));

    if (!(dest = fopen(path, "w"))) {
        merror("Couldn't open dest '%s': %s (%d)", path, strerror(errno), errno);
        fclose(source);
        return -1;
    }

    while (nbytes = fread(buffer, 1, 4096, source), nbytes) {
        if (fwrite(buffer, 1, nbytes, dest) != nbytes) {
            unlink(path);
            result = -1;
            break;
        }
    }

    fclose(source);
    if (fclose(dest) == -1) {
        merror("Couldn't create file %s completely ", path);
        return -1;
    }

    if (result < 0) {
        unlink(path);
        return -1;
    }

    if (chmod(path, 0640) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        unlink(path);
        return -1;
    }

    return 0;
}

int wdb_adjust_upgrade(wdb_t *wdb, int upgrade_step) {
    switch (upgrade_step) {
        case 3:
            return wdb_adjust_v4(wdb);
        default:
            return 0;
    }
}

int wdb_adjust_global_upgrade(wdb_t *wdb, int upgrade_step) {
    switch (upgrade_step) {
        case 3:
            return wdb_global_adjust_v4(wdb);
        default:
            return 0;
    }
}

int wdb_adjust_v4(wdb_t *wdb) {

    if (wdb_begin2(wdb) < 0) {
        merror("DB(%s) The begin statement could not be executed.", wdb->id);
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_GET_ATTRIBUTES) < 0) {
        merror("DB(%s) Can't cache statement: get_attributes.", wdb->id);
        return -1;
    }

    sqlite3_stmt *get_stmt = wdb->stmt[WDB_STMT_FIM_GET_ATTRIBUTES];
    char decoded_attrs[OS_SIZE_256];

    while (sqlite3_step(get_stmt) == SQLITE_ROW) {
        const char *file = (char *) sqlite3_column_text(get_stmt, 0);
        const char *attrs = (char *) sqlite3_column_text(get_stmt, 1);

        if (!file || !attrs || !isdigit(*attrs)) {
            continue;
        }

        decode_win_attributes(decoded_attrs, (unsigned int) atoi(attrs));

        if (wdb_stmt_cache(wdb, WDB_STMT_FIM_UPDATE_ATTRIBUTES) < 0) {
            merror("DB(%s) Can't cache statement: update_attributes.", wdb->id);
            return -1;
        }

        sqlite3_stmt *update_stmt = wdb->stmt[WDB_STMT_FIM_UPDATE_ATTRIBUTES];

        sqlite3_bind_text(update_stmt, 1, decoded_attrs, -1, NULL);
        sqlite3_bind_text(update_stmt, 2, file, -1, NULL);

        if (sqlite3_step(update_stmt) != SQLITE_DONE) {
            mdebug1("DB(%s) The attribute coded as %s could not be updated.", wdb->id, attrs);
        }
    }

    if (wdb_commit2(wdb) < 0) {
        merror("DB(%s) The commit statement could not be executed.", wdb->id);
        return -1;
    }

    return 0;
}

// Check the presence of manager's keepalive in the global database
int wdb_upgrade_check_manager_keepalive(wdb_t *wdb) {
    sqlite3_stmt *stmt = NULL;
    int result = -1;

    if (sqlite3_prepare_v2(wdb->db,
                           SQL_GLOBAL_STMT[WDB_STMT_GLOBAL_CHECK_MANAGER_KEEPALIVE],
                           -1,
                           &stmt,
                           NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        result = sqlite3_column_int(stmt, 0);
        break;
    case SQLITE_DONE:
        result = OS_SUCCESS;
        break;
    default:
        result = OS_INVALID;
    }

    sqlite3_finalize(stmt);
    return result;
}
