// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

/*
 * Ceph - scalable distributed file system
 *
 * Copyright (c) 2025 Huawei Technologies Co., Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 */

#include "openssl_opts_handler.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include "common/debug.h"
#include "global/global_context.h"
#include "include/str_list.h"
#include "include/scope_guard.h"

using std::string;
using std::string_view;
using std::ostream;

// -----------------------------------------------------------------------------
#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_common
#undef dout_prefix
#define dout_prefix _prefix(_dout)

static ostream &_prefix(std::ostream *_dout)
{
  return *_dout << "OpenSSLOptsHandler: ";
}

// -----------------------------------------------------------------------------

static string get_openssl_error()
{
  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == nullptr) {
    return "failed to create BIO for more error printing";
  }
  ERR_print_errors(bio);
  char* buf;
  size_t len = BIO_get_mem_data(bio, &buf);
  string ret(buf, len);
  BIO_free(bio);
  return ret;
}

static void log_error(const string &opt_name, const string_view &err)
{
  derr << "Intended OpenSSL acceleration failed.\n"
       << "set by " << opt_name << " = "
       << g_ceph_context->_conf.get_val<std::string>(opt_name)
       << "\ndetail error information:\n" << err << dendl;
}

static void load_modules(BIO *bio, const string &opt_name)
{
  CONF *conf = NCONF_new(nullptr);
  if (conf == nullptr) {
    log_error(opt_name, "failed to new OpenSSL CONF");
    return;
  }

  auto sg_conf = make_scope_guard([conf] { NCONF_free(conf); });

  if (NCONF_load_bio(conf, bio, nullptr) <= 0) {
    log_error(opt_name, "failed to load CONF from BIO:\n" + get_openssl_error());
    return;
  }

  OPENSSL_load_builtin_modules();

  if (CONF_modules_load(
          conf, nullptr,
          CONF_MFLAGS_DEFAULT_SECTION | CONF_MFLAGS_IGNORE_MISSING_FILE) <= 0) {
    log_error(opt_name, "failed to load modules from CONF:\n" + get_openssl_error());
  }
}

static void load_openssl_modules(const string &openssl_conf)
{
  BIO *bio = BIO_new_file(openssl_conf.c_str(), "r");
  if (bio == nullptr) {
    log_error("openssl_conf", "failed to open openssl conf");
    return;
  }

  auto sg_bio = make_scope_guard([bio] { BIO_free(bio); });

  load_modules(bio, "openssl_conf");
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

static string construct_provider_conf(const string &opts)
{
  const string conf_header = "openssl_conf=openssl_def\n[openssl_def]\n";
  const string provider_header = "providers=provider_section\n[provider_section]\n";
  string statement, detail;
  int index = 1;
  for (const auto &conf : get_str_vec(opts, ":")) {
    string id = "provider" + std::to_string(index++);
    statement += id + "=" + id + "_section\n";
    detail += "[" + id + "_section]\n";
    for (const auto &kv : get_str_vec(conf, ",")) {
      // Activation is managed, not configurable: the option exists to
      // load-and-activate providers, and OpenSSL 3.0.x activates on the
      // mere presence of an activate= key regardless of its value
      // (crypto/provider_conf.c, OpenSSL 3.0.13), so passing a
      // user-supplied value through would only mislead.
      if (kv.rfind("activate=", 0) == 0) {
        derr << "openssl_provider_opts: ignoring '" << kv
             << "' in provider stanza '" << conf
             << "': provider activation is managed automatically" << dendl;
        continue;
      }
      detail += kv + "\n";
    }
    detail += "activate=1\n";
  }
  return conf_header + provider_header + statement + detail;
}

static void load_provider_modules(const string &conf_str)
{
  BIO *bio = BIO_new_mem_buf(conf_str.c_str(), conf_str.size());
  if (bio == nullptr) {
    log_error("openssl_provider_opts", "failed to new BIO memory");
    return;
  }

  auto sg_bio = make_scope_guard([bio] { BIO_free(bio); });

  load_modules(bio, "openssl_provider_opts");
}

// OpenSSL 3.0.x's provider config module treats a provider that fails
// to activate as a non-fatal error: CONF_modules_load() still returns
// success (crypto/provider_conf.c, provider_conf_load(), OpenSSL
// 3.0.13), so a broken openssl_provider_opts value would be silently
// ignored.  Verify each requested provider is actually available and
// log loudly (but non-fatally) when it is not.
static void verify_providers_available(const string &opts)
{
  for (const auto &stanza : get_str_vec(opts, ":")) {
    string identity;
    for (const auto &kv : get_str_vec(stanza, ",")) {
      if (kv.rfind("identity=", 0) == 0) {
        identity = kv.substr(sizeof("identity=") - 1);
      }
    }
    if (identity.empty()) {
      log_error("openssl_provider_opts",
                "provider stanza is missing identity=<provider-name>: " + stanza);
      continue;
    }
    if (OSSL_PROVIDER_available(nullptr, identity.c_str()) != 1) {
      log_error("openssl_provider_opts",
                "provider '" + identity + "' is not available after load:\n" +
                    get_openssl_error());
    }
  }
}

#endif // OPENSSL_VERSION_NUMBER >= 0x30000000L

static void init_openssl()
{
  string openssl_conf = g_ceph_context->_conf.get_val<std::string>("openssl_conf");
  if (!openssl_conf.empty()) {
    load_openssl_modules(openssl_conf);
  }

  string provider_opts =
      g_ceph_context->_conf.get_val<std::string>("openssl_provider_opts");
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (!provider_opts.empty()) {
    load_provider_modules(construct_provider_conf(provider_opts));
    verify_providers_available(provider_opts);
  }
#else
  if (!provider_opts.empty()) {
    derr << "openssl_provider_opts requires OpenSSL >= 3.0; ignored" << dendl;
  }
#endif
}

void ceph::crypto::init_openssl_once()
{
  static std::once_flag flag;
  std::call_once(flag, init_openssl);
}
