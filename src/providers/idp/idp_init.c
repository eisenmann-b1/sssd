/*
    SSSD

    IdP Provider Initialization functions

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2024 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <jansson.h>
#include <stdbool.h>
#include <jose/b64.h>

#include "src/providers/data_provider.h"

#include "src/providers/idp/idp_common.h"
#include "src/providers/idp/idp_opts.h"
#include "src/providers/idp/idp_id.h"
#include "src/providers/idp/idp_auth.h"
#include "lib/idmap/sss_idmap.h"
#include "util/util_sss_idmap.h"

struct idp_init_ctx {
    struct be_ctx *be_ctx;
    struct dp_option *opts;
    struct idp_id_ctx *id_ctx;
    struct idp_auth_ctx *auth_ctx;

    const char *idp_type;
    const char *client_id;
    const char *client_secret;
    const char *token_endpoint;
    const char *scope;
};

static void token_refresh_table_delete_cb(hash_entry_t *item,
                                          hash_destroy_enum type,
                                          void *pvt) {
    struct idp_refresh_data *refresh_data = talloc_get_type(item->value.ptr,
                                                       struct idp_refresh_data);

    // If the request is already in progress, its handler will free the data.
    if (refresh_data->req != NULL && tevent_req_is_in_progress(refresh_data->req)) {
        return;
    }

    talloc_free(refresh_data);
}

static int get_jwt_payload(const char *str, json_t **out) {
    const char *sep;
    const char *payload_str;
    size_t payload_len;
    json_t *payload_obj;

    DEBUG(SSSDBG_TRACE_ALL, "@@@ Got JWT: [%s]\n", str);

    sep = strchr(str, '.');
    if (sep == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing first dot in JWT.\n");
        return EINVAL;
    }
    sep++;

    payload_str = sep;
    DEBUG(SSSDBG_TRACE_ALL, "@@@ Got start of payload: [%s]\n", payload_str);

    sep = strchr(sep, '.');
    if (sep == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing second dot in JWT.\n");
        return EINVAL;
    }
    payload_len = sep - payload_str;
    DEBUG(SSSDBG_TRACE_ALL, "@@@ Got payload: [%.*s]\n", (int)payload_len, payload_str);

    payload_obj = jose_b64_dec_load(json_stringn(payload_str, payload_len));
    if (payload_obj == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed decoding JWT payload.\n");
        return EINVAL;
    }

    *out = payload_obj;
    return EOK;
}

static int get_json_timestamp(const json_t *obj, const char *attr, time_t *out) {
    json_t *attr_obj;

    attr_obj = json_object_get(obj, attr);
    if (attr_obj == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed getting JSON attribute [%s]\n", attr);
        return EINVAL;
    }

    if (!json_is_integer(attr_obj)) {
        DEBUG(SSSDBG_OP_FAILURE, "Not integer type for JSON attribute [%s]\n", attr);
        return EINVAL;
    }

    *out = json_integer_value(attr_obj);
    return EOK;
}

static int get_jwt_timestamps(const char *str, time_t *iat_out, time_t *exp_out) {
    json_t *payload;
    int ret;

    ret = get_jwt_payload(str, &payload);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed getting JWT payload.\n");
        goto done;
    }

    if (iat_out != NULL) {
        ret = get_json_timestamp(payload, "iat", iat_out);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed getting JWT issued-at timestamp.\n");
            goto cleanup;
        }
    }

    if (exp_out != NULL) {
        ret = get_json_timestamp(payload, "exp", exp_out);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed getting JWT expiration timestamp.\n");
            goto cleanup;
        }
    }

cleanup:
    json_decref(payload);

done:
    return ret;
}

static bool is_jwt_expired(const char *str) {
    time_t expires_at;
    time_t now;
    int ret;

    ret = get_jwt_timestamps(str, NULL, &expires_at);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_ALL, "Failed getting expiration timestamp.\n");
        return false;
    }

    now = time(NULL);

    return expires_at <= now;
}

static int create_token_refresh_timers_from_cache(struct idp_auth_ctx *auth_ctx) {
    const char *attrs[] = {
        SYSDB_NAME,
        SYSDB_UUID,
        SYSDB_ACCESS_TOKEN,
        SYSDB_REFRESH_TOKEN,
        NULL,
    };
    struct sss_domain_info *dom = auth_ctx->be_ctx->domain;
    struct ldb_message **msgs = NULL;
    size_t msgs_count = 0;
    int ret;

    void *tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate temporary context.\n");
        return ENOMEM;
    }

    ret = sysdb_search_users(tmp_ctx, dom,
                             "(" SYSDB_UUID "=*)"
                             "(" SYSDB_ACCESS_TOKEN "=*)"
                             "(" SYSDB_REFRESH_TOKEN "=*)",
                             attrs, &msgs_count, &msgs);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to search for cached users.\n");
        }
        goto done;
    }

    for (int i = 0; i < msgs_count; i++) {
        struct ldb_message *msg = msgs[i];

        char *dn = ldb_dn_canonical_string(tmp_ctx, msg->dn);
        const char *user_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        const char *user_uuid = ldb_msg_find_attr_as_string(msg, SYSDB_UUID, NULL);
        const char *access_token = ldb_msg_find_attr_as_string(msg, SYSDB_ACCESS_TOKEN, NULL);
        const char *refresh_token = ldb_msg_find_attr_as_string(msg, SYSDB_REFRESH_TOKEN, NULL);

        time_t issued_at, expires_at;

        DEBUG(SSSDBG_TRACE_ALL, "@@ Found user with dn: [%s]\n", dn);
        DEBUG(SSSDBG_TRACE_ALL, "@@ Found user with name: [%s]\n", user_name);
        DEBUG(SSSDBG_TRACE_ALL, "@@ Found user with uuid: [%s]\n", user_uuid);
        DEBUG(SSSDBG_TRACE_ALL, "@@ Found user with access token: [%s]\n", access_token);
        DEBUG(SSSDBG_TRACE_ALL, "@@ Found user with refresh token: [%s]\n", refresh_token);

        DEBUG(SSSDBG_TRACE_ALL, "Trying to schedule token refresh for [%s].\n", user_uuid);
        if (is_jwt_expired(refresh_token)) {
            DEBUG(SSSDBG_TRACE_ALL, "Refresh token for user [%s] is expired.\n", user_uuid);
            continue;
        }

        ret = get_jwt_timestamps(access_token, &issued_at, &expires_at);
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_ALL, "Failed getting timestamps.\n");
            continue;
        }

        // timers created in the past will be scheduled immediately.
        ret = create_refresh_token_timer(auth_ctx, dom->name, user_name, user_uuid, issued_at, expires_at);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed creating token refresh timer.\n");
            continue;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t idp_get_options(TALLOC_CTX *mem_ctx,
                               struct confdb_ctx *cdb,
                               const char *conf_path,
                               struct dp_option **_opts)
{
    int ret;
    struct dp_option *opts;

    ret = dp_get_options(mem_ctx, cdb, conf_path, default_idp_opts,
                         IDP_OPTS, &opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_get_options failed.\n");
        goto done;
    }

    *_opts = opts;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(opts);
    }

    return ret;
}

errno_t sssm_idp_init(TALLOC_CTX *mem_ctx,
                      struct be_ctx *be_ctx,
                      struct data_provider *provider,
                      const char *module_name,
                      void **_module_data)
{
    struct idp_init_ctx *init_ctx;
    errno_t ret;

    init_ctx = talloc_zero(mem_ctx, struct idp_init_ctx);
    if (init_ctx == NULL) {
        return ENOMEM;
    }

    init_ctx->be_ctx = be_ctx;

    /* Always initialize options since it is needed everywhere. */
    ret = idp_get_options(init_ctx, be_ctx->cdb, be_ctx->conf_path,
                          &init_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize IdP options "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* idp_type may be NULL */
    init_ctx->idp_type = dp_opt_get_cstring(init_ctx->opts, IDP_TYPE);

    init_ctx->client_id = dp_opt_get_cstring(init_ctx->opts,
                                             IDP_CLIENT_ID);
    if (init_ctx->client_id == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_client_id'.\n");
        ret = EINVAL;
        goto done;
    }

    init_ctx->client_secret = dp_opt_get_cstring(init_ctx->opts,
                                                 IDP_CLIENT_SECRET);
    if (init_ctx->client_secret == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option '"CONFDB_IDP_CLIENT_SECRET"'.\n");
        ret = EINVAL;
        goto done;
    }

    init_ctx->token_endpoint = dp_opt_get_cstring(init_ctx->opts,
                                                  IDP_TOKEN_ENDPOINT);
    if (init_ctx->token_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_token_endpoint'.\n");
        ret = EINVAL;
        goto done;
    }

    init_ctx->scope = dp_opt_get_cstring(init_ctx->opts, IDP_ID_SCOPE);
    if (init_ctx->scope == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_scope'.\n");
        ret = EINVAL;
        goto done;
    }

    *_module_data = init_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(init_ctx);
    }

    return ret;
}

enum idmap_error_code set_idmap_options(struct sss_idmap_ctx *idmap_ctx,
                                        struct dp_option *idp_options)
{
    enum idmap_error_code err;
    id_t idmap_lower;
    id_t idmap_upper;
    id_t rangesize;

    idmap_lower = dp_opt_get_int(idp_options, IDMAP_LOWER);
    idmap_upper = dp_opt_get_int(idp_options, IDMAP_UPPER);
    rangesize = dp_opt_get_int(idp_options, IDMAP_RANGESIZE);

    /* Validate that the values make sense */
    if (rangesize <= 0
            || idmap_upper <= idmap_lower
            || (idmap_upper-idmap_lower) < rangesize)
    {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid settings for range selection: "
               "[%"SPRIid"][%"SPRIid"][%"SPRIid"]\n",
               idmap_lower, idmap_upper, rangesize);
        return IDMAP_ERROR;
    }

    if (((idmap_upper - idmap_lower) % rangesize) != 0) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Range size does not divide evenly. Uppermost range will "
               "not be used\n");
    }

    err = sss_idmap_ctx_set_lower(idmap_ctx, idmap_lower);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set lower boundary of id-mapping range.\n");
        return err;
    }

    err |= sss_idmap_ctx_set_upper(idmap_ctx, idmap_upper);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set upper boundary of id-mapping range.\n");
        return err;
    }
    err |= sss_idmap_ctx_set_rangesize(idmap_ctx, rangesize);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set range size for id-mapping.\n");
        return err;
    }

    return IDMAP_SUCCESS;
}

errno_t sssm_idp_id_init(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         void *module_data,
                         struct dp_method *dp_methods)
{
    struct idp_init_ctx *init_ctx;
    struct idp_id_ctx *id_ctx;
    errno_t ret;
    enum idmap_error_code err;
    struct sss_idmap_range id_range;

    init_ctx = talloc_get_type(module_data, struct idp_init_ctx);

    id_ctx = talloc_zero(init_ctx, struct idp_id_ctx);
    if (id_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to allocate memory for id context.\n");
        return ENOMEM;
    }

    id_ctx->be_ctx = be_ctx;
    id_ctx->init_ctx = init_ctx;
    id_ctx->idp_options = init_ctx->opts;

    id_ctx->idp_type = init_ctx->idp_type;
    id_ctx->client_id = init_ctx->client_id;
    id_ctx->client_secret = init_ctx->client_secret;
    id_ctx->token_endpoint = init_ctx->token_endpoint;
    id_ctx->scope = init_ctx->scope;

    err = sss_idmap_init(sss_idmap_talloc, init_ctx, sss_idmap_talloc_free,
                         &id_ctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed in initialize id-mapping: [%s].\n",
                                   idmap_error_string(err));
        ret = EINVAL;
        goto done;
    }

    err = set_idmap_options(id_ctx->idmap_ctx, id_ctx->idp_options);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set id-mapping options [%s].\n",
                                   idmap_error_string(err));
        ret = EINVAL;
        goto done;
    }

    /* TODO: The range_id (2nd parameter) should be configurable */
    err = sss_idmap_calculate_range(id_ctx->idmap_ctx, id_ctx->token_endpoint,
                                    NULL, &id_range);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to calculate id range for [%s]: [%s].\n",
              id_ctx->token_endpoint, idmap_error_string(err));
        ret = EINVAL;
        goto done;
    }

    err = sss_idmap_add_gen_domain_ex(id_ctx->idmap_ctx, be_ctx->domain->name,
                                      id_ctx->token_endpoint, &id_range,
                                      NULL, NULL, NULL, NULL, 0, false);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to add id-mapping domain [%s]: [%s].\n",
              be_ctx->domain->name, idmap_error_string(err));
        ret = EINVAL;
        goto done;
    }


    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  idp_account_info_handler_send, idp_account_info_handler_recv, id_ctx,
                  struct idp_id_ctx, struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_CHECK_ONLINE,
                  idp_online_check_handler_send, idp_online_check_handler_recv, id_ctx,
                  struct idp_id_ctx, void, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    init_ctx->id_ctx = id_ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(id_ctx);
    }

    return ret;
}

errno_t sssm_idp_auth_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           void *module_data,
                           struct dp_method *dp_methods)
{
    struct idp_init_ctx *init_ctx;
    struct idp_auth_ctx *auth_ctx;
    int ret;

    init_ctx = talloc_get_type(module_data, struct idp_init_ctx);

    auth_ctx = talloc_zero(init_ctx, struct idp_auth_ctx);
    if (auth_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to allocate memory for auth context.\n");
        return ENOMEM;
    }

    auth_ctx->be_ctx = be_ctx;
    auth_ctx->init_ctx = init_ctx;
    auth_ctx->idp_options = init_ctx->opts;

    auth_ctx->idp_type = init_ctx->idp_type;
    auth_ctx->client_id = init_ctx->client_id;
    auth_ctx->client_secret = init_ctx->client_secret;
    auth_ctx->token_endpoint = init_ctx->token_endpoint;

    auth_ctx->open_request_table = sss_ptr_hash_create(auth_ctx, NULL, NULL);
    if (auth_ctx->open_request_table == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create hash table for open requests.\n");
        ret = ENOMEM;
        goto done;
    }

    if (dp_opt_get_bool(init_ctx->opts, IDP_AUTO_REFRESH)) {
        auth_ctx->token_refresh_table = sss_ptr_hash_create(auth_ctx,
                                                  token_refresh_table_delete_cb,
                                                  NULL);
        if (auth_ctx->token_refresh_table == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to create hash table for token refreshes.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = create_token_refresh_timers_from_cache(auth_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to schedule token refreshes from cache.\n");
            // goto done;
        }
    }

    auth_ctx->scope = dp_opt_get_cstring(init_ctx->opts, IDP_AUTH_SCOPE);
    if (auth_ctx->scope == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_auth_scope'.\n");
        ret = EINVAL;
        goto done;
    }

    auth_ctx->device_auth_endpoint = dp_opt_get_cstring(init_ctx->opts,
                                                      IDP_DEVICE_AUTH_ENDPOINT);
    if (auth_ctx->device_auth_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_device_code_endpoint'.\n");
        ret = EINVAL;
        goto done;
    }

    auth_ctx->userinfo_endpoint = dp_opt_get_cstring(init_ctx->opts,
                                                     IDP_USERINFO_ENDPOINT);
    if (auth_ctx->userinfo_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_userinfo_endpoint'.\n");
        ret = EINVAL;
        goto done;
    }

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  idp_pam_auth_handler_send, idp_pam_auth_handler_recv, auth_ctx,
                  struct idp_auth_ctx, struct pam_data, struct pam_data *);

    init_ctx->auth_ctx = auth_ctx;
    ret =  EOK;
done:
    if (ret != EOK) {
        talloc_free(auth_ctx);
    }

    return ret;
}
