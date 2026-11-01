//! Gateway dynamic CA support.
//!
//! Generates and caches per-hostname leaf certificates signed by a configured
//! dynamic CA so agentgateway can terminate TLS using a certificate that matches
//! the downstream client's SNI. A client inside an explicit CONNECT tunnel that
//! sends no SNI, as is standard for IP-address URLs, gets a certificate for the
//! CONNECT authority instead.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use quick_cache::sync::Cache;
use rcgen::{CertificateParams, DnType, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, DnsName, PrivatePkcs8KeyDer};
use rustls::server::{NoServerSessionStorage, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::transport::tls;
use crate::types::agent::{ServerTLSConfig, TLSVersion};

struct DynamicCa {
	cert_der: Vec<u8>,
	issuer: Issuer<'static, KeyPair>,
}

impl DynamicCa {
	fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<Self> {
		let cert_pem_str = std::str::from_utf8(cert_pem)?;
		let key_pem_str = std::str::from_utf8(key_pem)?;

		let cert_der = CertificateDer::pem_slice_iter(cert_pem)
			.next()
			.ok_or_else(|| anyhow!("no certificate found in dynamic CA PEM"))?
			.map_err(|e| anyhow!("failed to parse dynamic CA cert PEM: {e}"))?
			.to_vec();

		let key_pair = KeyPair::from_pem(key_pem_str)?;
		let issuer = Issuer::from_ca_cert_pem(cert_pem_str, key_pair)?;

		Ok(Self { cert_der, issuer })
	}

	fn generate_leaf_cert(&self, domain: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
		let mut params = CertificateParams::new(vec![domain.to_string()])?;
		params.distinguished_name.push(DnType::CommonName, domain);
		params.is_ca = rcgen::IsCa::NoCa;
		params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
		params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
		params.use_authority_key_identifier_extension = true;

		let leaf_key = KeyPair::generate()?;
		let leaf_cert = params.signed_by(&leaf_key, &self.issuer)?;

		Ok((leaf_cert.der().to_vec(), leaf_key.serialize_der()))
	}
}

#[derive(Clone)]
struct CachedDynamicCaCert {
	certified_key: Arc<CertifiedKey>,
	issued_at: Instant,
}

pub(super) struct DynamicCaCertResolver {
	ca: Arc<DynamicCa>,
	provider: Arc<rustls::crypto::CryptoProvider>,
	cache: Cache<String, CachedDynamicCaCert>,
	cache_ttl: Duration,
}

impl std::fmt::Debug for DynamicCaCertResolver {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("DynamicCaCertResolver").finish()
	}
}

impl DynamicCaCertResolver {
	pub(super) fn new(
		ca_cert_pem: &[u8],
		ca_key_pem: &[u8],
		cache_config: &crate::DynamicCaCertCacheConfig,
	) -> anyhow::Result<Arc<Self>> {
		Ok(Arc::new(Self {
			ca: Arc::new(DynamicCa::from_pem(ca_cert_pem, ca_key_pem)?),
			provider: tls::provider(),
			cache: Cache::new(cache_config.capacity),
			cache_ttl: cache_config.ttl,
		}))
	}

	fn cached_fresh_entry(
		entry: &CachedDynamicCaCert,
		now: Instant,
		cache_ttl: Duration,
	) -> Option<Arc<CertifiedKey>> {
		if now.duration_since(entry.issued_at) <= cache_ttl {
			return Some(Arc::clone(&entry.certified_key));
		}
		None
	}

	fn generate_certified_key(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
		let (leaf_der, key_der) = self.ca.generate_leaf_cert(domain).ok()?;

		let cert_chain = vec![
			CertificateDer::from(leaf_der),
			CertificateDer::from(self.ca.cert_der.clone()),
		];

		let private_key = PrivatePkcs8KeyDer::from(key_der);
		let signing_key = crate::crypto::tls::key_provider(&self.provider)
			.load_private_key(private_key.into())
			.ok()?;

		Some(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
	}

	fn cached_certified_key(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
		let now = Instant::now();
		if let Some(entry) = self.cache.get(domain) {
			if let Some(certified_key) = Self::cached_fresh_entry(&entry, now, self.cache_ttl) {
				return Some(certified_key);
			}
			self.cache.remove_if(domain, |entry| {
				Self::cached_fresh_entry(entry, now, self.cache_ttl).is_none()
			});
		}

		let certified_key = self.generate_certified_key(domain)?;

		let now = Instant::now();
		if let Some(entry) = self.cache.get(domain) {
			if let Some(existing) = Self::cached_fresh_entry(&entry, now, self.cache_ttl) {
				return Some(existing);
			}
			self.cache.remove_if(domain, |entry| {
				Self::cached_fresh_entry(entry, now, self.cache_ttl).is_none()
			});
		}

		self.cache.insert(
			domain.to_string(),
			CachedDynamicCaCert {
				certified_key: Arc::clone(&certified_key),
				issued_at: now,
			},
		);

		Some(certified_key)
	}
}

impl ResolvesServerCert for DynamicCaCertResolver {
	fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		let domain = client_hello.server_name()?;
		self.cached_certified_key(domain)
	}
}

/// Serves a certificate for a CONNECT authority on one connection that sent no SNI.
/// The issued certificates stay in the listener's shared [`DynamicCaCertResolver`].
#[derive(Debug)]
struct ConnectAuthorityCertResolver {
	inner: Arc<DynamicCaCertResolver>,
	identity: String,
}

impl ResolvesServerCert for ConnectAuthorityCertResolver {
	fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		self.inner.cached_certified_key(&self.identity)
	}
}

/// Normalizes a CONNECT authority to the DNS name or IP address its certificate must
/// name. Returns `None` if the host is neither, so that no certificate is issued.
fn connect_authority_identity(authority: &http::uri::Authority) -> Option<String> {
	let host = authority.host();
	if let Some(ip) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
		return ip.parse::<Ipv6Addr>().ok().map(|ip| ip.to_string());
	}
	if let Ok(ip) = host.parse::<Ipv4Addr>() {
		return Some(ip.to_string());
	}
	DnsName::try_from(host).ok()?;
	Some(host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase())
}

/// Derives the config for a single connection that sent no SNI inside a CONNECT tunnel.
/// Everything but the certificate selection and resumption is inherited from `config`.
///
/// Resumption is disabled because rustls only requires that the SNI of a resumed session
/// matches. Every connection on this path has no SNI, so the shared session storage would
/// let a session established for one CONNECT authority resume under another without a
/// certificate for it ever being presented.
///
/// An authority that is neither a DNS name nor an IP address leaves `config` in place,
/// which fails the handshake as for any other connection without SNI.
pub(super) fn server_config_for_connect_authority(
	config: Arc<rustls::ServerConfig>,
	resolver: &Arc<DynamicCaCertResolver>,
	authority: &http::uri::Authority,
) -> Arc<rustls::ServerConfig> {
	let Some(identity) = connect_authority_identity(authority) else {
		return config;
	};
	let mut config = (*config).clone();
	config.cert_resolver = Arc::new(ConnectAuthorityCertResolver {
		inner: Arc::clone(resolver),
		identity,
	});
	config.session_storage = Arc::new(NoServerSessionStorage {});
	config.send_tls13_tickets = 0;
	Arc::new(config)
}

pub(super) fn build_dynamic_ca_server_config(
	resolver: Arc<DynamicCaCertResolver>,
	alpns: Option<&[Vec<u8>]>,
	default_alpns: &[Vec<u8>],
	min_version: Option<TLSVersion>,
	max_version: Option<TLSVersion>,
	cipher_suites: &[tls::CipherSuite],
	key_exchange_groups: &[tls::KeyExchangeGroup],
) -> anyhow::Result<rustls::ServerConfig> {
	let provider = tls::provider_with_options_validated(cipher_suites, key_exchange_groups)?;

	let versions = super::agent::tls_versions_for_range(min_version, max_version)?;
	let mut config = rustls::ServerConfig::builder_with_provider(provider)
		.with_protocol_versions(&versions)
		.expect("server config must be valid")
		.with_no_client_auth()
		.with_cert_resolver(resolver);
	config.key_log = tls::key_log();
	config.alpn_protocols = alpns
		.map(|a| a.to_vec())
		.unwrap_or_else(|| default_alpns.to_vec());

	Ok(config)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_dynamic_ca_tls_config_with_profile(
	ca_cert_pem: Vec<u8>,
	ca_key_pem: Vec<u8>,
	default_alpns: Vec<Vec<u8>>,
	min_version: Option<TLSVersion>,
	max_version: Option<TLSVersion>,
	cipher_suites: Option<Vec<tls::CipherSuite>>,
	key_exchange_groups: Option<Vec<tls::KeyExchangeGroup>>,
	cache_config: crate::DynamicCaCertCacheConfig,
) -> anyhow::Result<ServerTLSConfig> {
	ServerTLSConfig::dynamic_ca_with_profile(
		ca_cert_pem,
		ca_key_pem,
		default_alpns,
		min_version,
		max_version,
		cipher_suites,
		key_exchange_groups,
		cache_config,
	)
}

#[cfg(test)]
mod tests {
	use rcgen::{BasicConstraints, IsCa, KeyUsagePurpose};
	use rustls::pki_types::ServerName;
	use rustls::{ClientConfig, ClientConnection, ConnectionCommon, HandshakeKind, ServerConnection};
	use x509_parser::extensions::{GeneralName, ParsedExtension};
	use x509_parser::prelude::{FromDer, X509Certificate};

	use super::*;

	fn ca_params(common_name: &str) -> CertificateParams {
		let mut params = CertificateParams::default();
		params
			.distinguished_name
			.push(DnType::CommonName, common_name);
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
		params
	}

	fn subject_key_identifier(cert_der: &[u8]) -> Vec<u8> {
		let (_, cert) = X509Certificate::from_der(cert_der).expect("parse certificate");
		cert
			.extensions()
			.iter()
			.find_map(|extension| match extension.parsed_extension() {
				ParsedExtension::SubjectKeyIdentifier(key_identifier) => Some(key_identifier.0.to_vec()),
				_ => None,
			})
			.expect("certificate has a subject key identifier")
	}

	fn authority_key_identifier(cert_der: &[u8]) -> Vec<u8> {
		let (_, cert) = X509Certificate::from_der(cert_der).expect("parse certificate");
		cert
			.extensions()
			.iter()
			.find_map(|extension| match extension.parsed_extension() {
				ParsedExtension::AuthorityKeyIdentifier(authority_key_identifier) => {
					authority_key_identifier
						.key_identifier
						.as_ref()
						.map(|key_identifier| key_identifier.0.to_vec())
				},
				_ => None,
			})
			.expect("certificate has an authority key identifier")
	}

	fn test_resolver() -> DynamicCaCertResolver {
		let ca_key = rcgen::KeyPair::generate().expect("generate CA key");
		let mut ca_params = rcgen::CertificateParams::default();
		ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
		let ca_cert = ca_params.self_signed(&ca_key).expect("generate CA cert");

		DynamicCaCertResolver {
			ca: Arc::new(
				DynamicCa::from_pem(ca_cert.pem().as_bytes(), ca_key.serialize_pem().as_bytes())
					.expect("parse CA"),
			),
			provider: tls::provider(),
			cache: Cache::new(crate::DynamicCaCertCacheConfig::default().capacity),
			cache_ttl: crate::DynamicCaCertCacheConfig::default().ttl,
		}
	}

	#[test]
	fn cached_certified_key_reuses_fresh_entry() {
		let resolver = test_resolver();

		let first = resolver
			.cached_certified_key("example.com")
			.expect("generate cert");
		let second = resolver
			.cached_certified_key("example.com")
			.expect("cache hit");

		assert!(Arc::ptr_eq(&first, &second));
	}

	#[test]
	fn cached_certified_key_replaces_expired_entry() {
		let resolver = DynamicCaCertResolver {
			cache_ttl: Duration::from_nanos(0),
			..test_resolver()
		};

		let first = resolver
			.cached_certified_key("example.com")
			.expect("generate cert");
		let second = resolver
			.cached_certified_key("example.com")
			.expect("generate replacement cert");

		assert!(!Arc::ptr_eq(&first, &second));
	}

	#[test]
	fn leaf_authority_key_identifier_matches_self_signed_ca() {
		let ca_key = KeyPair::generate().expect("generate CA key");
		let ca_cert = ca_params("dynamic CA")
			.self_signed(&ca_key)
			.expect("generate CA cert");
		let dynamic_ca =
			DynamicCa::from_pem(ca_cert.pem().as_bytes(), ca_key.serialize_pem().as_bytes())
				.expect("parse CA");

		let (leaf_der, _) = dynamic_ca
			.generate_leaf_cert("example.com")
			.expect("generate leaf");

		assert_eq!(
			authority_key_identifier(&leaf_der),
			subject_key_identifier(ca_cert.der())
		);
	}

	#[test]
	fn intermediate_ca_signs_leaf_and_is_served_in_chain() {
		let root_key = KeyPair::generate().expect("generate root key");
		let root_params = ca_params("root CA");
		let root_cert = root_params
			.self_signed(&root_key)
			.expect("generate root cert");
		let root_issuer = Issuer::new(root_params, root_key);

		let intermediate_key = KeyPair::generate().expect("generate intermediate key");
		let mut intermediate_params = ca_params("dynamic intermediate CA");
		intermediate_params.use_authority_key_identifier_extension = true;
		let intermediate_cert = intermediate_params
			.signed_by(&intermediate_key, &root_issuer)
			.expect("generate intermediate cert");
		let intermediate_der = intermediate_cert.der().to_vec();
		let dynamic_ca = DynamicCa::from_pem(
			intermediate_cert.pem().as_bytes(),
			intermediate_key.serialize_pem().as_bytes(),
		)
		.expect("parse intermediate CA");
		let resolver = DynamicCaCertResolver {
			ca: Arc::new(dynamic_ca),
			provider: tls::provider(),
			cache: Cache::new(crate::DynamicCaCertCacheConfig::default().capacity),
			cache_ttl: crate::DynamicCaCertCacheConfig::default().ttl,
		};

		let certified_key = resolver
			.generate_certified_key("example.com")
			.expect("generate certified key");
		assert_eq!(certified_key.cert.len(), 2);
		assert_eq!(certified_key.cert[1].as_ref(), intermediate_der);

		let leaf_aki = authority_key_identifier(certified_key.cert[0].as_ref());
		assert_eq!(leaf_aki, subject_key_identifier(&intermediate_der));
		assert_ne!(leaf_aki, subject_key_identifier(root_cert.der()));
	}

	fn authority(authority: &str) -> http::uri::Authority {
		authority.parse().expect("valid authority")
	}

	struct TestCa {
		cert_pem: String,
		key_pem: String,
	}

	impl TestCa {
		fn new() -> Self {
			let key = KeyPair::generate().expect("generate CA key");
			let cert = ca_params("dynamic CA")
				.self_signed(&key)
				.expect("generate CA cert");
			Self {
				cert_pem: cert.pem(),
				key_pem: key.serialize_pem(),
			}
		}

		fn resolver(&self) -> Arc<DynamicCaCertResolver> {
			DynamicCaCertResolver::new(
				self.cert_pem.as_bytes(),
				self.key_pem.as_bytes(),
				&Default::default(),
			)
			.expect("build resolver")
		}

		fn client_config(
			&self,
			version: &'static rustls::SupportedProtocolVersion,
			enable_sni: bool,
		) -> Arc<ClientConfig> {
			let mut roots = rustls::RootCertStore::empty();
			let (added, _) = roots.add_parsable_certificates(
				CertificateDer::pem_slice_iter(self.cert_pem.as_bytes()).map(|c| c.expect("CA PEM")),
			);
			assert_eq!(added, 1);
			let mut config = ClientConfig::builder_with_provider(tls::provider())
				.with_protocol_versions(&[version])
				.expect("client versions")
				.with_root_certificates(roots)
				.with_no_client_auth();
			config.enable_sni = enable_sni;
			Arc::new(config)
		}
	}

	fn server_config(resolver: &Arc<DynamicCaCertResolver>) -> Arc<rustls::ServerConfig> {
		Arc::new(
			build_dynamic_ca_server_config(
				Arc::clone(resolver),
				None,
				&[b"h2".to_vec(), b"http/1.1".to_vec()],
				None,
				None,
				&[],
				&[],
			)
			.expect("build server config"),
		)
	}

	/// Runs a real handshake, including delivery of TLS 1.3 tickets, in memory.
	fn handshake(
		client_config: &Arc<ClientConfig>,
		server_config: &Arc<rustls::ServerConfig>,
		name: &str,
	) -> Result<(ClientConnection, ServerConnection), rustls::Error> {
		fn transfer<A, B>(
			from: &mut ConnectionCommon<A>,
			to: &mut ConnectionCommon<B>,
		) -> Result<bool, rustls::Error> {
			let mut sent = false;
			while from.wants_write() {
				let mut buf = Vec::new();
				from.write_tls(&mut buf).expect("write to memory");
				let mut buf = buf.as_slice();
				while !buf.is_empty() {
					to.read_tls(&mut buf).expect("read from memory");
					to.process_new_packets()?;
				}
				sent = true;
			}
			Ok(sent)
		}

		let name = ServerName::try_from(name.to_string()).expect("valid server name");
		let mut client = ClientConnection::new(Arc::clone(client_config), name)?;
		let mut server = ServerConnection::new(Arc::clone(server_config))?;
		loop {
			let client_sent = transfer(&mut client, &mut server)?;
			let server_sent = transfer(&mut server, &mut client)?;
			if !client_sent && !server_sent {
				return Ok((client, server));
			}
		}
	}

	fn leaf_subject_alt_names(cert_der: &[u8]) -> Vec<String> {
		let (_, cert) = X509Certificate::from_der(cert_der).expect("parse certificate");
		cert
			.subject_alternative_name()
			.expect("parse SAN")
			.expect("certificate has a SAN")
			.value
			.general_names
			.iter()
			.map(|name| match name {
				GeneralName::DNSName(name) => format!("dns:{name}"),
				GeneralName::IPAddress(ip) => match ip.len() {
					4 => format!(
						"ip:{}",
						Ipv4Addr::from(<[u8; 4]>::try_from(*ip).expect("IPv4 length"))
					),
					16 => format!(
						"ip:{}",
						Ipv6Addr::from(<[u8; 16]>::try_from(*ip).expect("IPv6 length"))
					),
					len => panic!("unexpected IP SAN length {len}"),
				},
				other => panic!("unexpected SAN {other:?}"),
			})
			.collect()
	}

	fn presented_subject_alt_names(client: &ClientConnection) -> Vec<String> {
		leaf_subject_alt_names(
			client
				.peer_certificates()
				.expect("server presented a certificate")[0]
				.as_ref(),
		)
	}

	const VERSIONS: [&rustls::SupportedProtocolVersion; 2] =
		[&rustls::version::TLS12, &rustls::version::TLS13];

	#[test]
	fn connect_authority_identity_normalizes_hosts() {
		for (input, expected) in [
			("192.0.2.10:443", Some("192.0.2.10")),
			("[2001:db8::10]:443", Some("2001:db8::10")),
			// IPv6 is compared by value, so its spelling must not fragment the cache.
			("[2001:DB8:0:0::10]:443", Some("2001:db8::10")),
			("[::ffff:192.0.2.10]:443", Some("::ffff:192.0.2.10")),
			("Api.Example.TEST:443", Some("api.example.test")),
			("api.example.test.:443", Some("api.example.test")),
			("user:pass@api.example.test:443", Some("api.example.test")),
			("api.example.test", Some("api.example.test")),
			// Not a certifiable identity: never issue for these.
			("*.example.test:443", None),
			("[192.0.2.10]:443", None),
			("[fe80::1%25en0]:443", None),
			("256.256.256.256:443", None),
			("127.1:443", None),
			("2130706433:443", None),
			("0x7f.1:443", None),
			("example..test:443", None),
			("example.test..:443", None),
		] {
			assert_eq!(
				connect_authority_identity(&authority(input)).as_deref(),
				expected,
				"authority {input}"
			);
		}
	}

	#[test]
	fn no_sni_connect_authority_issues_verifiable_ip_and_dns_certificates() {
		let ca = TestCa::new();
		let resolver = ca.resolver();
		let base = server_config(&resolver);
		for version in VERSIONS {
			for (connect, client_name, enable_sni, san) in [
				("192.0.2.10:443", "192.0.2.10", true, "ip:192.0.2.10"),
				(
					"[2001:db8::10]:443",
					"2001:db8::10",
					true,
					"ip:2001:db8::10",
				),
				(
					"api.example.test:443",
					"api.example.test",
					false,
					"dns:api.example.test",
				),
			] {
				let config =
					server_config_for_connect_authority(base.clone(), &resolver, &authority(connect));
				let (client, server) =
					handshake(&ca.client_config(version, enable_sni), &config, client_name)
						.unwrap_or_else(|e| panic!("{connect} should verify: {e}"));
				assert_eq!(presented_subject_alt_names(&client), vec![san.to_string()]);
				assert_eq!(server.server_name(), None, "client sent no SNI");
			}
		}
	}

	#[test]
	fn no_sni_without_usable_identity_fails_handshake() {
		let ca = TestCa::new();
		let resolver = ca.resolver();
		let base = server_config(&resolver);
		let client = ca.client_config(&rustls::version::TLS13, true);

		// Without CONNECT the base config applies: no certificate, no guessing.
		assert!(handshake(&client, &base, "192.0.2.10").is_err());

		// An invalid CONNECT host does not issue a certificate either.
		let config =
			server_config_for_connect_authority(base.clone(), &resolver, &authority("127.1:443"));
		assert!(Arc::ptr_eq(&config, &base));
		assert!(handshake(&client, &config, "192.0.2.10").is_err());
	}

	#[test]
	fn no_sni_certificate_is_rejected_for_other_targets_and_cas() {
		let ca = TestCa::new();
		let resolver = ca.resolver();
		let base = server_config(&resolver);
		let client = ca.client_config(&rustls::version::TLS13, false);
		let config =
			server_config_for_connect_authority(base.clone(), &resolver, &authority("192.0.2.10:443"));

		for wrong_name in ["192.0.2.11", "2001:db8::10", "api.example.test"] {
			assert!(
				handshake(&client, &config, wrong_name).is_err(),
				"certificate for 192.0.2.10 must not verify for {wrong_name}"
			);
		}
		let other_ca = TestCa::new().client_config(&rustls::version::TLS13, false);
		assert!(handshake(&other_ca, &config, "192.0.2.10").is_err());
	}

	#[test]
	fn concurrent_no_sni_connections_keep_their_own_identity_and_share_the_cache() {
		let ca = TestCa::new();
		let resolver = ca.resolver();
		let base = server_config(&resolver);
		let client = ca.client_config(&rustls::version::TLS13, true);
		let targets: Vec<_> = (1..=16).map(|i| format!("192.0.2.{i}")).collect();

		std::thread::scope(|scope| {
			for target in &targets {
				// Two connections race for each target.
				for _ in 0..2 {
					let (resolver, base, client) = (&resolver, &base, &client);
					scope.spawn(move || {
						let config = server_config_for_connect_authority(
							base.clone(),
							resolver,
							&authority(&format!("{target}:443")),
						);
						let (conn, _) = handshake(client, &config, target).expect("handshake");
						assert_eq!(
							presented_subject_alt_names(&conn),
							vec![format!("ip:{target}")]
						);
					});
				}
			}
		});

		for target in &targets {
			assert!(
				resolver.cache.get(target.as_str()).is_some(),
				"{target} must be cached in the shared resolver"
			);
		}
		assert!(
			handshake(&client, &base, &targets[0]).is_err(),
			"per-connection identities must not leak into the shared config"
		);
	}

	#[test]
	fn no_sni_connect_authority_does_not_resume_sessions() {
		let ca = TestCa::new();
		let resolver = ca.resolver();
		let base = server_config(&resolver);
		for version in VERSIONS {
			// The same client config keeps a session cache, so it offers any session it holds.
			let client = ca.client_config(version, true);
			for _ in 0..2 {
				let config = server_config_for_connect_authority(
					base.clone(),
					&resolver,
					&authority("192.0.2.10:443"),
				);
				let (conn, _) = handshake(&client, &config, "192.0.2.10").expect("handshake");
				assert_eq!(conn.handshake_kind(), Some(HandshakeKind::Full));
			}
		}
	}

	#[test]
	fn sni_connections_on_shared_config_still_resume() {
		let ca = TestCa::new();
		let base = server_config(&ca.resolver());
		for version in VERSIONS {
			let client = ca.client_config(version, true);
			let (first, _) = handshake(&client, &base, "api.example.test").expect("handshake");
			assert_eq!(first.handshake_kind(), Some(HandshakeKind::Full));
			let (second, server) = handshake(&client, &base, "api.example.test").expect("handshake");
			assert_eq!(second.handshake_kind(), Some(HandshakeKind::Resumed));
			assert_eq!(server.server_name(), Some("api.example.test"));
		}
	}
}
