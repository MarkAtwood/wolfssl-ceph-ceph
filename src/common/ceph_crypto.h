// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
#ifndef CEPH_CRYPTO_H
#define CEPH_CRYPTO_H

#include "acconfig.h"
#include <stdexcept>
#include <vector>

#include "include/common_fwd.h"
#include "include/buffer.h"
#include "include/types.h"

#define CEPH_CRYPTO_MD5_DIGESTSIZE 16
#define CEPH_CRYPTO_HMACSHA1_DIGESTSIZE 20
#define CEPH_CRYPTO_SHA1_DIGESTSIZE 20
#define CEPH_CRYPTO_HMACSHA256_DIGESTSIZE 32
#define CEPH_CRYPTO_SHA256_DIGESTSIZE 32
#define CEPH_CRYPTO_HMACSHA512_DIGESTSIZE 64
#define CEPH_CRYPTO_SHA512_DIGESTSIZE 64

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/hmac.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif

#include "include/ceph_assert.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

extern "C" {
  const EVP_MD *EVP_md5(void);
  const EVP_MD *EVP_sha1(void);
  const EVP_MD *EVP_sha256(void);
  const EVP_MD *EVP_sha512(void);
}

namespace TOPNSPC::crypto {
  void assert_init();
  void init();
  void shutdown(bool shared=true);

  void zeroize_for_security(void *s, size_t n);

  class DigestException : public std::runtime_error
  {
    public:
      DigestException(const char* what_arg) : runtime_error(what_arg)
	{}
  };

  namespace ssl {
    class OpenSSLDigest {
      private:
	EVP_MD_CTX *mpContext;
	const EVP_MD *mpType;
        EVP_MD *mpType_FIPS = nullptr;
      public:
	OpenSSLDigest (const EVP_MD *_type);
	~OpenSSLDigest ();
	OpenSSLDigest(OpenSSLDigest&& o) noexcept;
	OpenSSLDigest& operator=(OpenSSLDigest&& o) noexcept;
	void Restart();
	void SetFlags(int flags);
	void Update (const unsigned char *input, size_t length);
	void Final (unsigned char *digest);
    };

    class MD5 : public OpenSSLDigest {
      public:
	static constexpr size_t digest_size = CEPH_CRYPTO_MD5_DIGESTSIZE;
	MD5 () : OpenSSLDigest(EVP_md5()) { }
    };

    // MD5 for non-cryptographic purposes (S3/Swift ETags, object names,
    // cache keys).  On OpenSSL 3+ the digest is fetched with a "fips=no"
    // property query so it stays available when the default property
    // query is "fips=yes"; this replaces the former
    // SetFlags(EVP_MD_CTX_FLAG_NON_FIPS_ALLOW), which has been a no-op
    // since OpenSSL 3.0.
    class MD5NonCrypto : public OpenSSLDigest {
	static const EVP_MD *digest_type();  // in ceph_crypto.cc
      public:
	static constexpr size_t digest_size = CEPH_CRYPTO_MD5_DIGESTSIZE;
	MD5NonCrypto () : OpenSSLDigest(digest_type()) { }
    };

    class SHA1 : public OpenSSLDigest {
      public:
        static constexpr size_t digest_size = CEPH_CRYPTO_SHA1_DIGESTSIZE;
        SHA1 () : OpenSSLDigest(EVP_sha1()) { }
    };

    class SHA256 : public OpenSSLDigest {
      public:
        static constexpr size_t digest_size = CEPH_CRYPTO_SHA256_DIGESTSIZE;
        SHA256 () : OpenSSLDigest(EVP_sha256()) { }
    };

    class SHA512 : public OpenSSLDigest {
      public:
        static constexpr size_t digest_size = CEPH_CRYPTO_SHA512_DIGESTSIZE;
        SHA512 () : OpenSSLDigest(EVP_sha512()) { }
    };

# if OPENSSL_VERSION_NUMBER < 0x10100000L
  class HMAC {
  private:
    HMAC_CTX mContext;
    const EVP_MD *mpType;

  public:
    HMAC (const EVP_MD *type, const unsigned char *key, size_t length)
      : mpType(type) {
      // the strict FIPS zeroization doesn't seem to be necessary here.
      // just in the case.
      ::TOPNSPC::crypto::zeroize_for_security(&mContext, sizeof(mContext));
      const auto r = HMAC_Init_ex(&mContext, key, length, mpType, nullptr);
      if (r != 1) {
	  throw DigestException("HMAC_Init_ex() failed");
      }
    }
    ~HMAC () {
      HMAC_CTX_cleanup(&mContext);
    }

    void Restart () {
      const auto r = HMAC_Init_ex(&mContext, nullptr, 0, mpType, nullptr);
      if (r != 1) {
	throw DigestException("HMAC_Init_ex() failed");
      }
    }
    void Update (const unsigned char *input, size_t length) {
      if (length) {
        const auto r = HMAC_Update(&mContext, input, length);
	if (r != 1) {
	  throw DigestException("HMAC_Update() failed");
	}
      }
    }
    void Final (unsigned char *digest) {
      unsigned int s;
      const auto r = HMAC_Final(&mContext, digest, &s);
      if (r != 1) {
	throw DigestException("HMAC_Final() failed");
      }
    }
  };
# elif OPENSSL_VERSION_NUMBER < 0x30000000L
  class HMAC {
  private:
    HMAC_CTX *mpContext;

  public:
    HMAC (const EVP_MD *type, const unsigned char *key, size_t length)
      : mpContext(HMAC_CTX_new()) {
      const auto r = HMAC_Init_ex(mpContext, key, length, type, nullptr);
      if (r != 1) {
	throw DigestException("HMAC_Init_ex() failed");
      }
    }
    ~HMAC () {
      HMAC_CTX_free(mpContext);
    }

    void Restart () {
      const EVP_MD * const type = HMAC_CTX_get_md(mpContext);
      const auto r = HMAC_Init_ex(mpContext, nullptr, 0, type, nullptr);
      if (r != 1) {
	throw DigestException("HMAC_Init_ex() failed");
      }
    }
    void Update (const unsigned char *input, size_t length) {
      if (length) {
        const auto r = HMAC_Update(mpContext, input, length);
	if (r != 1) {
	  throw DigestException("HMAC_Update() failed");
	}
      }
    }
    void Final (unsigned char *digest) {
      unsigned int s;
      const auto r = HMAC_Final(mpContext, digest, &s);
      if (r != 1) {
	throw DigestException("HMAC_Final() failed");
      }
    }
  };
# else
  // OpenSSL 3.x deprecated the HMAC_CTX API. Use EVP_MAC so the whole
  // keyed-hash construction, not just the underlying digest, is served
  // by the provider selected in the library context.
  class HMAC {
  private:
    static EVP_MAC *get_evp_mac() {
      // process-lifetime cache; deliberately never freed, matching the
      // lifetime OpenSSL gives its own implicitly fetched algorithms
      static EVP_MAC * const mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
      return mac;
    }
    EVP_MAC_CTX *mpContext;
    // kept so Restart() can re-key explicitly; see below
    std::vector<unsigned char> mKey;

  public:
    HMAC (const EVP_MD *type, const unsigned char *key, size_t length)
      : mKey(key, key + length) {
      EVP_MAC * const mac = get_evp_mac();
      if (mac == nullptr) {
	throw DigestException("EVP_MAC_fetch() failed");
      }
      mpContext = EVP_MAC_CTX_new(mac);
      if (mpContext == nullptr) {
	throw DigestException("EVP_MAC_CTX_new() failed");
      }
      const OSSL_PARAM params[] = {
	OSSL_PARAM_construct_utf8_string(
	  OSSL_MAC_PARAM_DIGEST,
	  const_cast<char*>(EVP_MD_get0_name(type)), 0),
	OSSL_PARAM_construct_end()
      };
      const auto r = EVP_MAC_init(mpContext, key, length, params);
      if (r != 1) {
	EVP_MAC_CTX_free(mpContext);
	throw DigestException("EVP_MAC_init() failed");
      }
    }
    ~HMAC () {
      EVP_MAC_CTX_free(mpContext);
      if (!mKey.empty()) {
	::TOPNSPC::crypto::zeroize_for_security(mKey.data(), mKey.size());
      }
    }

    void Restart () {
      // re-key explicitly rather than passing a NULL key: the reference
      // provider re-keys and resets on a NULL-key init (since 3.0.3,
      // openssl/openssl#17811), but that is not part of the EVP_MAC
      // contract and other providers keep the running state instead.
      // The digest established at construction persists in the context.
      const auto r = EVP_MAC_init(mpContext, mKey.data(), mKey.size(),
				  nullptr);
      if (r != 1) {
	throw DigestException("EVP_MAC_init() failed");
      }
    }
    void Update (const unsigned char *input, size_t length) {
      if (length) {
        const auto r = EVP_MAC_update(mpContext, input, length);
	if (r != 1) {
	  throw DigestException("EVP_MAC_update() failed");
	}
      }
    }
    void Final (unsigned char *digest) {
      size_t s;
      const auto r = EVP_MAC_final(mpContext, digest, &s,
				   EVP_MAC_CTX_get_mac_size(mpContext));
      if (r != 1) {
	throw DigestException("EVP_MAC_final() failed");
      }
    }
  };
# endif // OPENSSL_VERSION_NUMBER < 0x10100000L

  struct HMACSHA1 : public HMAC {
    HMACSHA1 (const unsigned char *key, size_t length)
      : HMAC(EVP_sha1(), key, length) {
    }
  };

  struct HMACSHA256 : public HMAC {
    HMACSHA256 (const unsigned char *key, size_t length)
      : HMAC(EVP_sha256(), key, length) {
    }
  };

  struct HMACSHA512 : public HMAC {
    HMACSHA512 (const unsigned char *key, size_t length)
      : HMAC(EVP_sha512(), key, length) {
    }
  };
}


  using ssl::SHA256;
  using ssl::MD5;
  using ssl::MD5NonCrypto;
  using ssl::SHA1;
  using ssl::SHA512;

  using ssl::HMACSHA256;
  using ssl::HMACSHA1;
  using ssl::HMACSHA512;

template<class Digest>
auto digest(const ceph::buffer::list& bl)
{
  unsigned char fingerprint[Digest::digest_size];
  Digest gen;
  for (auto& p : bl.buffers()) {
    gen.Update((const unsigned char *)p.c_str(), p.length());
  }
  gen.Final(fingerprint);
  return sha_digest_t<Digest::digest_size>{fingerprint};
}
}

#pragma clang diagnostic pop
#pragma GCC diagnostic pop

#endif
