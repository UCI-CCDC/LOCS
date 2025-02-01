mod config {
    use crate::scan::OsType;
    use crate::util::ip::convert_to_cidr;
    use anyhow::Context;
    use cidr::IpCidr;
    use serde::{Deserialize, Serialize};
    use std::io::{BufRead, Write};
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use std::{
        collections::{HashMap, HashSet},
        fs::File,
        io::BufReader,
        io::BufWriter,
        net::IpAddr,
        path::{Path, PathBuf},
    };
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Host {
        pub ip: IpAddr,
        pub user: String,
        pub pass: Option<String>,
        pub port: u16,
        pub open_ports: HashSet<u16>,
        pub aliases: HashSet<String>,
        pub os: OsType,
        pub desc: HashSet<String>,
    }
    impl Host {
        pub fn name(&self) -> String {
            self.aliases
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| self.ip.to_string())
        }
    }
    impl std::fmt::Display for Host {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.name())
        }
    }
    #[derive(Serialize, Deserialize)]
    struct ConfigFile {
        pub hosts: HashMap<IpAddr, Host>,
        pub cidr: Option<IpCidr>,
        pub long_timeout: Duration,
        pub short_timeout: Duration,
        pub excluded_octets: Vec<u8>,
        pub linux_root: String,
        pub windows_root: String,
    }
    impl ConfigFile {
        pub fn new() -> Self {
            Self {
                hosts: HashMap::new(),
                cidr: None,
                long_timeout: Duration::from_secs(15),
                short_timeout: Duration::from_millis(150),
                excluded_octets: vec![1, 2],
                linux_root: "root".into(),
                windows_root: "Administrator".into(),
            }
        }
    }
    pub struct Config {
        file: ConfigFile,
        path: PathBuf,
    }
    impl Config {
        pub fn new() -> Config {
            Config {
                file: ConfigFile::new(),
                path: PathBuf::from("blaze.yaml"),
            }
        }
        pub fn set_cidr(&mut self, cidr: IpCidr) {
            self.file.cidr = Some(cidr);
        }
        pub fn get_cidr(&self) -> Option<IpCidr> {
            self.file.cidr
        }
        pub fn from(path: &PathBuf) -> anyhow::Result<Config> {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            Ok(Config {
                file: serde_yaml::from_reader(reader).context("couldn't parse config file")?,
                path: path.clone(),
            })
        }
        pub fn save(&self) -> anyhow::Result<()> {
            let file = File::create(&self.path)?;
            let writer = BufWriter::new(file);
            Ok(serde_yaml::to_writer(writer, &self.file)?)
        }
        pub fn host_for_ip(&self, ip: IpAddr) -> Option<&Host> {
            self.file.hosts.get(&ip)
        }
        pub fn host_for_ip_mut(&mut self, ip: IpAddr) -> Option<&mut Host> {
            self.file.hosts.get_mut(&ip)
        }
        pub fn host_for_octet(&self, octet: u8) -> Option<&Host> {
            let cidr = self.get_cidr()?;
            let ip = Ipv4Addr::from_bits(octet as u32);
            let ip = convert_to_cidr(cidr, ip.into()).ok()?;
            self.host_for_ip(ip)
        }
        pub fn host_for_octet_mut(&mut self, octet: u8) -> Option<&mut Host> {
            let cidr = self.get_cidr()?;
            let ip = Ipv4Addr::from_bits(octet as u32);
            let ip = convert_to_cidr(cidr, ip.into()).ok()?;
            self.host_for_ip_mut(ip)
        }
        pub fn host_for_alias(&self, alias: &str) -> Option<&Host> {
            let mut iter = self.hosts().iter().filter_map(|(_, host)| {
                if host
                    .aliases
                    .iter()
                    .any(|a| a.to_lowercase().starts_with(&alias.to_lowercase()))
                {
                    Some(host)
                } else {
                    None
                }
            });
            iter.next().and_then(|host| {
                if let Some(_) = iter.next() {
                    None
                } else {
                    Some(host)
                }
            })
        }
        pub fn host_for_alias_mut(&mut self, alias: &str) -> Option<&mut Host> {
            let mut iter = self.hosts_mut().iter_mut().filter_map(|(_, host)| {
                if host
                    .aliases
                    .iter()
                    .any(|a| a.to_lowercase().starts_with(&alias.to_lowercase()))
                {
                    Some(host)
                } else {
                    None
                }
            });
            iter.next().and_then(|host| {
                if let Some(_) = iter.next() {
                    None
                } else {
                    Some(host)
                }
            })
        }
        pub fn get_excluded_octets(&self) -> &Vec<u8> {
            &self.file.excluded_octets
        }
        pub fn set_excluded_octets(&mut self, octets: &Vec<u8>) {
            self.file.excluded_octets = octets.clone()
        }
        pub fn add_host(&mut self, host: &Host) {
            self.file.hosts.insert(host.ip, host.clone());
        }
        pub fn remove_host(&mut self, ip: &IpAddr) -> Option<Host> {
            self.file.hosts.remove(ip)
        }
        pub fn add_host_from(
            &mut self,
            scan_host: &crate::scan::Host,
            user: String,
            pass: Option<String>,
            port: u16,
        ) -> anyhow::Result<()> {
            let host = Host {
                ip: scan_host.addr,
                user,
                pass,
                port,
                open_ports: scan_host.ports.clone(),
                aliases: HashSet::new(),
                os: scan_host.os,
                desc: HashSet::new(),
            };
            self.file.hosts.insert(host.ip, host);
            Ok(())
        }
        pub fn hosts(&self) -> &HashMap<IpAddr, Host> {
            &self.file.hosts
        }
        pub fn script_hosts(&self) -> Box<dyn Iterator<Item = (&IpAddr, &Host)> + '_> {
            let runnable = self
                .hosts()
                .iter()
                .filter(|(_, host)| host.open_ports.contains(&22));
            match self.get_cidr() {
                Some(cidr) => Box::new(runnable.filter(move |(ip, _)| {
                    self.get_excluded_octets()
                        .iter()
                        .filter_map(|octet| {
                            let ip = Ipv4Addr::from_bits(*octet as u32);
                            convert_to_cidr(cidr, ip.into()).ok()
                        })
                        .all(|addr| addr != **ip)
                })),
                None => Box::new(runnable),
            }
        }
        pub fn hosts_mut(&mut self) -> &mut HashMap<IpAddr, Host> {
            &mut self.file.hosts
        }
        pub fn export_compat(&self, filename: &Path) -> anyhow::Result<()> {
            let file = File::create(filename)?;
            let mut writer = BufWriter::new(file);
            for (_, host) in self
                .file
                .hosts
                .iter()
                .filter(|(_, host)| host.os == OsType::UnixLike && host.pass.is_some())
            {
                let aliases: Vec<_> = host.aliases.iter().cloned().collect();
                let aliases = aliases.join(" ");
                let line = format!(
                    "{} {} {} {} {}",
                    host.ip,
                    host.user,
                    host.pass.as_ref().unwrap(),
                    host.port,
                    aliases
                );
                writeln!(writer, "{}", line.trim())?;
            }
            Ok(())
        }
        pub fn import_compat(&mut self, filename: &Path) -> anyhow::Result<()> {
            let file = File::open(filename)?;
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let fields = line.split(" ").collect::<Vec<_>>();
                if fields.len() < 4 {
                    anyhow::bail!("invalid line format in legacy file format");
                }
                let ip = fields[0].parse()?;
                let user = fields[1].to_owned();
                let pass = fields[2].to_owned();
                let port: u16 = fields[3].parse()?;
                let aliases = fields[4..].iter().map(|alias| alias.to_string()).collect();
                let host = Host {
                    ip,
                    user,
                    pass: Some(pass),
                    port,
                    aliases,
                    open_ports: HashSet::new(),
                    os: OsType::UnixLike,
                    desc: HashSet::new(),
                };
                self.add_host(&host);
            }
            Ok(())
        }
        pub fn get_long_timeout(&self) -> Duration {
            self.file.long_timeout
        }
        pub fn set_long_timeout(&mut self, timeout: Duration) {
            self.file.long_timeout = timeout;
        }
        pub fn get_short_timeout(&self) -> Duration {
            self.file.short_timeout
        }
        pub fn set_short_timeout(&mut self, timeout: Duration) {
            self.file.short_timeout = timeout;
        }
        pub fn linux_root(&self) -> &str {
            &self.file.linux_root
        }
        pub fn windows_root(&self) -> &str {
            &self.file.windows_root
        }
    }
    impl Drop for Config {
        fn drop(&mut self) {
            let _ = self.save();
        }
    }
}
mod proto {
    pub mod ldap {
        use ldap3::{Ldap, LdapConnAsync, ResultEntry, Scope, SearchEntry, drive};
        use std::net::IpAddr;
        pub struct Session {
            domain: String,
            handle: Ldap,
        }
        pub struct Computer {
            pub name: String,
            pub dns_name: String,
            pub os: Option<String>,
            pub os_version: Option<String>,
        }
        pub struct User {
            pub name: String,
            pub id: String,
            pub admin: bool,
        }
        impl Session {
            pub async fn new(
                ip: IpAddr,
                domain: &str,
                user: &str,
                pass: &str,
            ) -> anyhow::Result<Self> {
                let dcs: Vec<_> = domain.split(".").map(|dc| format!("DC={}", dc)).collect();
                let domain = dcs.join(",");
                log::info!("Connecting to domain {}", domain);
                let (conn, mut handle) = LdapConnAsync::new(&format!("ldap://{}", ip)).await?;
                drive!(conn);
                handle
                    .simple_bind(&format!("CN={},CN=Users,{}", user, domain), pass)
                    .await?
                    .success()?;
                Ok(Self { domain, handle })
            }
            fn get_first_attr(entry: &SearchEntry, key: &str) -> Option<String> {
                entry
                    .attrs
                    .get(key)
                    .map(|vec| vec.iter().next())
                    .flatten()
                    .cloned()
            }
            pub fn qualify(&self, container: &str) -> String {
                format!("{},{}", container, self.domain())
            }
            pub async fn search<'a, S, A>(
                &mut self,
                container: &str,
                filter: &str,
                attrs: A,
            ) -> anyhow::Result<Vec<ResultEntry>>
            where
                S: AsRef<str> + Send + Sync + 'a,
                A: AsRef<[S]> + Send + Sync + 'a,
            {
                let (entries, result) = self
                    .handle
                    .clone()
                    .search(&self.qualify(container), Scope::Subtree, filter, attrs)
                    .await?
                    .success()?;
                result.success()?;
                Ok(entries)
            }
            pub async fn computers(&mut self) -> anyhow::Result<Vec<Computer>> {
                let entries = self
                    .search("CN=Computers", "(objectClass=computer)", &vec![
                        "name",
                        "operatingSystem",
                        "operatingSystemVersion",
                        "dNSHostName",
                    ])
                    .await?;
                Ok(entries
                    .into_iter()
                    .filter_map(|entry| {
                        let entry = SearchEntry::construct(entry);
                        let name = entry.attrs.get("name")?.iter().next()?.clone();
                        let dns_name = entry.attrs.get("dNSHostName")?.iter().next()?.clone();
                        let os = Self::get_first_attr(&entry, "operatingSystem");
                        let os_version = Self::get_first_attr(&entry, "operatingSystemVersion");
                        Some(Computer {
                            name,
                            dns_name,
                            os,
                            os_version,
                        })
                    })
                    .collect())
            }
            pub async fn users(&mut self) -> anyhow::Result<Vec<User>> {
                let entries = self
                    .search("CN=Users", "(objectClass=person)", &vec![
                        "name",
                        "sAMAccountName",
                        "adminCount",
                    ])
                    .await?;
                Ok(entries
                    .into_iter()
                    .filter_map(|entry| {
                        let entry = SearchEntry::construct(entry);
                        let name = entry.attrs.get("name")?.iter().next()?.clone();
                        let id = entry.attrs.get("sAMAccountName")?.iter().next()?.clone();
                        let admin = entry.attrs.get("adminCount").is_some();
                        Some(User { name, id, admin })
                    })
                    .collect())
            }
            pub fn domain(&self) -> &str {
                &self.domain
            }
        }
        impl Drop for Session {
            fn drop(&mut self) {
                _ = self.handle.unbind();
            }
        }
    }
    pub mod rdp {
        use anyhow::Context;
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, ServerName};
        use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
        use std::marker::{Send, Sync};
        use std::net::IpAddr;
        use std::sync::Arc;
        use std::sync::mpsc::{Sender, channel};
        use std::time::Duration;
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        use x509_parser::der_parser::Oid;
        #[derive(Debug)]
        struct CertGrabber {
            send: Sender<String>,
        }
        unsafe impl Send for CertGrabber {}
        unsafe impl Sync for CertGrabber {}
        impl ServerCertVerifier for CertGrabber {
            fn verify_server_cert(
                &self,
                end_entity: &rustls::pki_types::CertificateDer<'_>,
                _: &[rustls::pki_types::CertificateDer<'_>],
                _: &rustls::pki_types::ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> Result<ServerCertVerified, Error> {
                let common_name_oid = Oid::from(&[2, 5, 4, 3]).map_err(|_| Error::DecryptError)?;
                let (_, cert) = x509_parser::parse_x509_certificate(&end_entity)
                    .map_err(|_| Error::DecryptError)?;
                for rdn in cert.subject().iter_rdn() {
                    for attr in rdn.iter() {
                        if attr.attr_type() == &common_name_oid {
                            if let Ok(value) = attr.as_str() {
                                _ = self.send.send(value.to_owned())
                            }
                        }
                    }
                }
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::RSA_PKCS1_SHA1,
                    SignatureScheme::ECDSA_SHA1_Legacy,
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SignatureScheme::ECDSA_NISTP521_SHA512,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::ED25519,
                    SignatureScheme::ED448,
                ]
            }
        }
        async fn do_grab_rdp_hostname(ip: IpAddr) -> anyhow::Result<String> {
            let (send, recv) = channel();
            let cfg = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(CertGrabber { send }))
                .with_no_client_auth();
            let server = ServerName::IpAddress(ip.into());
            let connector = TlsConnector::from(Arc::new(cfg));
            let sock = TcpStream::connect((ip, 3389))
                .await
                .context("failed to connect to rdp endpoint")?;
            connector.connect(server, sock).await?;
            Ok(recv.recv()?)
        }
        pub async fn grab_rdp_hostname(ip: IpAddr, timeout: Duration) -> anyhow::Result<String> {
            tokio::time::timeout(timeout, do_grab_rdp_hostname(ip)).await?
        }
    }
    pub mod ssh {
        use crate::scripts::Scripts;
        use anyhow::{Context, anyhow};
        use async_trait::async_trait;
        use crossterm::terminal;
        use russh::*;
        use russh_keys::key::PublicKey;
        use russh_sftp::client::SftpSession;
        use std::path::{Path, PathBuf};
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpStream, ToSocketAddrs};
        struct Handler;
        #[async_trait]
        impl client::Handler for Handler {
            type Error = russh::Error;
            async fn check_server_key(
                &mut self,
                _server_public_key: &PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }
        #[doc = " This struct is a convenience wrapper"]
        #[doc = " around a russh client"]
        #[doc = " that handles the input/output event loop"]
        pub struct Session {
            session: client::Handle<Handler>,
        }
        impl Session {
            pub async fn connect<A: ToSocketAddrs>(
                user: &str,
                pass: &str,
                addrs: A,
            ) -> anyhow::Result<Self> {
                let config = client::Config {
                    inactivity_timeout: Some(Duration::from_secs(86400)),
                    keepalive_interval: Some(Duration::from_secs(10)),
                    keepalive_max: 2,
                    ..<_>::default()
                };
                let config = Arc::new(config);
                let handler = Handler {};
                let mut session = client::connect(config, addrs, handler).await?;
                let auth_res = session.authenticate_password(user, pass).await?;
                if !auth_res {
                    anyhow::bail!("Authentication (with password) failed");
                }
                Ok(Self { session })
            }
            async fn do_read_server_id<A: ToSocketAddrs>(addrs: A) -> anyhow::Result<String> {
                let stream = TcpStream::connect(addrs)
                    .await
                    .context("failed to connect to tcp stream")?;
                stream.readable().await?;
                let mut data = vec![0; 1024];
                let count = stream.try_read(&mut data)?;
                Ok(String::from_utf8_lossy(&data[..count]).into())
            }
            pub async fn get_server_id<A: ToSocketAddrs>(
                addrs: A,
                timeout: Duration,
            ) -> anyhow::Result<String> {
                tokio::time::timeout(timeout, Self::do_read_server_id(addrs)).await?
            }
            pub async fn upload(&mut self, file: &Path) -> anyhow::Result<String> {
                let filename = PathBuf::from(file)
                    .file_name()
                    .ok_or(anyhow!("couldn't find filename for script"))?
                    .to_string_lossy()
                    .into_owned();
                let mut src = Scripts::find(file)
                    .await
                    .ok_or(anyhow!("couldn't find script"))?;
                let sftp_channel = self.session.channel_open_session().await?;
                sftp_channel
                    .request_subsystem(true, "sftp")
                    .await
                    .context("couldn't request sftp subsystem")?;
                let sftp = SftpSession::new(sftp_channel.into_stream()).await?;
                let mut dst = sftp.create(&filename).await?;
                let mut meta = dst.metadata().await?;
                meta.permissions = Some(0o700);
                dst.set_metadata(meta)
                    .await
                    .context("couldn't change file permissions")?;
                tokio::io::copy(&mut src, &mut dst)
                    .await
                    .context("couldn't copy file to remote location")?;
                sftp.close().await?;
                Ok(filename.into())
            }
            pub async fn exec(
                &mut self,
                command: String,
                capture: bool,
            ) -> anyhow::Result<(u32, Vec<u8>)> {
                let mut channel = self.session.channel_open_session().await?;
                channel.exec(true, command).await?;
                let mut code = 0;
                let mut buffer: Vec<u8> = Vec::new();
                loop {
                    let Some(msg) = channel.wait().await else {
                        break;
                    };
                    match msg {
                        ChannelMsg::Data { ref data } => {
                            if capture {
                                buffer.extend_from_slice(data);
                            }
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            code = exit_status;
                        }
                        _ => {}
                    }
                }
                Ok((code, buffer))
            }
            pub async fn run_script(
                &mut self,
                script: &Path,
                args: Vec<String>,
                capture: bool,
                upload: bool,
            ) -> anyhow::Result<(u32, Vec<u8>)> {
                let script = self.upload(&script).await?;
                let script = format!("./{}", script);
                let cmd = shlex::try_join(
                    std::iter::once(&script)
                        .chain(args.iter())
                        .map(String::as_str),
                )?;
                log::info!("{}", cmd);
                let (code, output) = self.exec(cmd, capture).await?;
                if !upload {
                    self.exec(format!("rm {}", script), false).await?;
                }
                Ok((code, output))
            }
            pub async fn shell(&mut self) -> anyhow::Result<u32> {
                let mut channel = self.session.channel_open_session().await?;
                let (w, h) = terminal::size()?;
                channel
                    .request_pty(false, "xterm".into(), w as u32, h as u32, 0, 0, &[])
                    .await?;
                channel.request_shell(true).await?;
                let code;
                let mut stdout = tokio::io::stdout();
                let mut stdin = tokio::io::stdin();
                let mut buf = vec![0; 1000];
                let mut stdin_closed = false;
                terminal::enable_raw_mode()?;
                loop {
                    tokio::select! { r = stdin . read (& mut buf) , if ! stdin_closed => { match r { Ok (0) => { stdin_closed = true ; channel . eof () . await ?; } , Ok (n) => { if buf [.. n] . contains (& 17u8) { } channel . data (& buf [.. n]) . await ?; } , Err (e) => return Err (e . into ()) , } ; } , Some (msg) = channel . wait () => { match msg { ChannelMsg :: Data { ref data } => { stdout . write_all (data) . await ?; stdout . flush () . await ?; } ChannelMsg :: ExitStatus { exit_status } => { code = exit_status ; if ! stdin_closed { channel . eof () . await ?; } break ; } _ => { } } } , }
                }
                terminal::disable_raw_mode()?;
                Ok(code)
            }
            async fn close(&mut self) -> anyhow::Result<()> {
                self.session
                    .disconnect(Disconnect::ByApplication, "", "English")
                    .await?;
                Ok(())
            }
        }
    }
}
mod repl {
    use crate::config::Config as BlazeConfig;
    use crate::run::{BlazeCommand, run};
    use anyhow::Context;
    use clap::{CommandFactory, Parser};
    use rustyline::highlight::Highlighter;
    use rustyline::{
        CompletionType, Config, Editor, Helper, Hinter, Validator, completion::Completer,
        error::ReadlineError,
    };
    use std::ffi::OsString;
    const HISTORY_FILE: &str = ".blaze_history";
    #[derive(Helper, Hinter, Validator)]
    struct ClapCompleter;
    impl Completer for ClapCompleter {
        type Candidate = String;
        fn complete(
            &self,
            line: &str,
            _: usize,
            _: &rustyline::Context<'_>,
        ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
            let mut cmd = BlazeCommand::command();
            let args: Vec<_> = std::iter::once("blaze")
                .chain(line.split_whitespace())
                .map(OsString::from)
                .collect();
            let index = args.len() - 1;
            let matches = clap_complete::engine::complete(&mut cmd, args, index, None)
                .unwrap_or_else(|_| vec![]);
            Ok((
                0,
                matches
                    .into_iter()
                    .map(|m| m.get_value().to_string_lossy().into())
                    .collect(),
            ))
        }
    }
    impl Highlighter for ClapCompleter {}
    async fn do_run(cmd: BlazeCommand, cfg: &mut BlazeConfig) -> anyhow::Result<()> {
        tokio::select! { signal = tokio :: signal :: ctrl_c () => signal . context ("couldn't read ctrl+c handler") , result = run (cmd , cfg) => result , }
    }
    pub async fn repl(cfg: &mut BlazeConfig) -> anyhow::Result<()> {
        let config = Config::builder()
            .history_ignore_dups(true)?
            .history_ignore_space(false)
            .completion_type(CompletionType::List)
            .auto_add_history(true)
            .build();
        let mut reader: Editor<ClapCompleter, _> = Editor::with_config(config)?;
        reader.set_helper(Some(ClapCompleter));
        reader.load_history(HISTORY_FILE).unwrap_or_else(|e| {
            log::info!("Failed to load REPL history: {}, continuing", e);
        });
        loop {
            match reader.readline(">> ") {
                Ok(line) => match line.as_str() {
                    "exit" => break,
                    _ => {
                        let cmd = BlazeCommand::try_parse_from(
                            std::iter::once("blaze").chain(line.split_whitespace()),
                        );
                        match cmd {
                            Err(err) => println!("{}", err),
                            Ok(cmd) => {
                                let res = do_run(cmd, cfg).await;
                                if let Err(err) = res {
                                    log::error!("{}", err);
                                }
                            }
                        }
                    }
                },
                Err(ReadlineError::Eof) => break,
                Err(ReadlineError::Interrupted) => continue,
                Err(err) => log::error!("Couldn't read input: {}", err),
            }
        }
        reader.append_history(HISTORY_FILE)?;
        Ok(())
    }
}
mod run {
    use crate::config::Config;
    use clap::Parser;
    mod chpass {
        use crate::config::Config;
        use crate::proto::ssh::Session;
        use crate::run::script::{RunScriptArgs, run_script_all_args};
        use anyhow::Context;
        use rand::Rng;
        use serde::Deserialize;
        use std::path::PathBuf;
        #[derive(Deserialize)]
        struct Password {
            id: u32,
            password: String,
        }
        fn get_passwords() -> anyhow::Result<Vec<Password>> {
            let mut passwords = Vec::new();
            let mut reader = csv::Reader::from_path("passwords.db")?;
            for result in reader.deserialize() {
                passwords.push(result?);
            }
            Ok(passwords)
        }
        pub async fn chpass(_cmd: (), cfg: &mut Config) -> anyhow::Result<()> {
            let script = PathBuf::from("chpass.sh");
            let mut passwords = get_passwords()?;
            let mut rng = rand::thread_rng();
            let mut set = run_script_all_args(
                cfg.get_long_timeout(),
                cfg,
                |host| {
                    let rand = rng.gen_range(0..passwords.len());
                    let pass = passwords.remove(rand);
                    log::info!("Using password {} for host {}", pass.id, host);
                    vec![host.user.clone(), pass.password]
                },
                RunScriptArgs::new(script),
            )
            .await;
            let mut failed = Vec::<String>::new();
            while let Some(joined) = set.join_next().await {
                let (mut host, output) = joined.context("Error running password script")?;
                match output {
                    Ok((code, pass)) => {
                        if code != 0 {
                            log::warn!(
                                "Password script returned nonzero code {} for host {}",
                                code,
                                host
                            );
                        }
                        let pass = pass.trim();
                        log::info!(
                            "Ran password script on host {}, now checking password {}",
                            host,
                            pass
                        );
                        let session =
                            Session::connect(&host.user, pass, (host.ip, host.port)).await;
                        if let Err(err) = session {
                            log::error!("Password change seems to have failed, error: {}", err);
                            failed.push(host.to_string());
                        } else {
                            log::info!("Success, writing config file");
                            host.pass = Some(pass.into());
                            cfg.add_host(&host);
                        }
                    }
                    Err(err) => {
                        log::error!("Error running script on host {}: {}", host, err);
                        failed.push(host.to_string());
                    }
                }
            }
            log::info!(
                "Total: {} failed password changes (hosts {:?})",
                failed.len(),
                failed.join(" "),
            );
            Ok(())
        }
    }
    mod config {
        use crate::config::{Config, Host};
        use crate::scan::OsType;
        use crate::util::strings::{comma_join, join};
        use anyhow::Context;
        use clap::{Args, Subcommand, ValueEnum};
        use humantime::format_duration;
        use std::collections::HashSet;
        use std::net::IpAddr;
        use std::path::PathBuf;
        use std::time::Duration;
        pub fn lookup_host<'a>(cfg: &'a Config, host: &str) -> anyhow::Result<&'a Host> {
            match host.parse() {
                Ok(ip) => cfg
                    .host_for_ip(ip)
                    .with_context(|| format!("no host for ip {}", ip)),
                Err(_) => match host.parse() {
                    Ok(octet) => cfg
                        .host_for_octet(octet)
                        .with_context(|| format!("no host for octet {}", octet)),
                    Err(_) => cfg
                        .host_for_alias(host)
                        .with_context(|| format!("no host for alias {}", host)),
                },
            }
        }
        pub fn lookup_host_mut<'a>(
            cfg: &'a mut Config,
            host: &str,
        ) -> anyhow::Result<&'a mut Host> {
            match host.parse() {
                Ok(ip) => cfg
                    .host_for_ip_mut(ip)
                    .with_context(|| format!("no host for ip {}", ip)),
                Err(_) => match host.parse() {
                    Ok(octet) => cfg
                        .host_for_octet_mut(octet)
                        .with_context(|| format!("no host for octet {}", octet)),
                    Err(_) => cfg
                        .host_for_alias_mut(host)
                        .with_context(|| format!("no host for alias {}", host)),
                },
            }
        }
        #[derive(Args)]
        pub struct AddCommand {
            pub ip: IpAddr,
            # [arg (short , long , default_value_t = String :: from ("root"))]
            pub user: String,
            pub pass: String,
            #[arg(short, long, default_value_t = 22)]
            pub port: u16,
            #[arg(short, long, default_value = "unix-like")]
            pub os: OsType,
        }
        pub async fn add_host(cmd: AddCommand, cfg: &mut Config) -> anyhow::Result<()> {
            cfg.add_host(&Host {
                ip: cmd.ip,
                user: cmd.user,
                pass: Some(cmd.pass),
                port: cmd.port,
                open_ports: HashSet::new(),
                aliases: HashSet::new(),
                os: cmd.os,
                desc: HashSet::new(),
            });
            Ok(())
        }
        #[derive(Args)]
        pub struct RemoveCommand {
            pub host: String,
        }
        pub async fn remove_host(cmd: RemoveCommand, cfg: &mut Config) -> anyhow::Result<()> {
            let ip = {
                let host = lookup_host(&cfg, &cmd.host)?;
                host.ip.clone()
            };
            cfg.remove_host(&ip);
            Ok(())
        }
        #[derive(Args)]
        pub struct EditCommand {
            pub host: String,
            #[command(subcommand)]
            pub cmd: EditCommandEnum,
        }
        #[derive(Subcommand)]
        pub enum EditCommandEnum {
            User(EditUserCommand),
            #[clap(alias = "pw")]
            Pass(EditPassCommand),
            Os(EditOsCommand),
            Alias(EditAliasCommand),
        }
        #[derive(Args)]
        pub struct EditUserCommand {
            pub user: String,
        }
        #[derive(Args)]
        pub struct EditPassCommand {
            pub pass: String,
        }
        #[derive(Args)]
        pub struct EditOsCommand {
            pub os: OsType,
        }
        #[derive(Args)]
        pub struct EditAliasCommand {
            pub alias: String,
        }
        pub async fn edit_host(cmd: EditCommand, cfg: &mut Config) -> anyhow::Result<()> {
            let host = lookup_host_mut(cfg, &cmd.host)?;
            match cmd.cmd {
                EditCommandEnum::User(cmd) => host.user = cmd.user,
                EditCommandEnum::Pass(cmd) => host.pass = Some(cmd.pass),
                EditCommandEnum::Os(cmd) => host.os = cmd.os,
                EditCommandEnum::Alias(cmd) => _ = host.aliases.insert(cmd.alias),
            }
            Ok(())
        }
        #[derive(Args)]
        pub struct ListCommand {
            pub os: Option<OsType>,
        }
        pub async fn list_hosts(cmd: ListCommand, cfg: &mut Config) -> anyhow::Result<()> {
            for host in cfg
                .hosts()
                .values()
                .filter(|host| cmd.os.is_none() || Some(host.os) == cmd.os)
            {
                let aliases: Vec<String> = host.aliases.iter().cloned().collect();
                let aliases = if aliases.len() == 0 {
                    "<none>".into()
                } else {
                    aliases.join(", ")
                };
                let hoststr = format!("{}@{}:{}", host.user, host.ip, host.port);
                println!("{:<55} (aliases {})", hoststr, aliases);
            }
            println!(
                "Octets excluded from scripts: {}",
                comma_join(cfg.get_excluded_octets())
            );
            Ok(())
        }
        #[derive(Args)]
        pub struct InfoCommand {
            pub host: String,
        }
        pub async fn host_info(cmd: InfoCommand, cfg: &mut Config) -> anyhow::Result<()> {
            let host = lookup_host(cfg, &cmd.host)?;
            let aliases = if host.aliases.len() == 0 {
                "<none>".into()
            } else {
                comma_join(&host.aliases)
            };
            let ports = comma_join(&host.open_ports);
            println!("{} (aliases {})", host.ip, aliases);
            println!("Open ports: {}", ports);
            println!(
                "Password: {}",
                host.pass.as_ref().unwrap_or(&"<none>".into())
            );
            println!("Operating system: {:?}", host.os);
            println!("Description: {}", join(&host.desc, "\n             "));
            Ok(())
        }
        #[derive(Args)]
        pub struct ExportCommand {
            pub filename: PathBuf,
        }
        pub async fn export(cmd: ExportCommand, cfg: &mut Config) -> anyhow::Result<()> {
            cfg.export_compat(&cmd.filename)
        }
        #[derive(Args)]
        pub struct ExcludeCommand {
            pub octets: Vec<u8>,
        }
        pub async fn exclude(cmd: ExcludeCommand, cfg: &mut Config) -> anyhow::Result<()> {
            cfg.set_excluded_octets(&cmd.octets);
            Ok(())
        }
        #[derive(Args)]
        pub struct ImportCommand {
            pub filename: PathBuf,
        }
        pub async fn import(cmd: ImportCommand, cfg: &mut Config) -> anyhow::Result<()> {
            cfg.import_compat(&cmd.filename)
        }
        #[derive(Clone, PartialEq, Eq, ValueEnum)]
        pub enum TimeoutType {
            Short,
            Long,
        }
        #[derive(Args)]
        pub struct TimeoutCommand {
            # [clap (value_parser = humantime :: parse_duration)]
            #[arg(short, long)]
            pub timeout: Option<Duration>,
            #[arg(default_value = "short")]
            pub kind: TimeoutType,
        }
        pub async fn set_timeout(cmd: TimeoutCommand, cfg: &mut Config) -> anyhow::Result<()> {
            match cmd.timeout {
                Some(timeout) => match cmd.kind {
                    TimeoutType::Short => cfg.set_short_timeout(timeout),
                    TimeoutType::Long => cfg.set_long_timeout(timeout),
                },
                None => match cmd.kind {
                    TimeoutType::Short => println!(
                        "Short timeout is {}",
                        format_duration(cfg.get_short_timeout())
                    ),
                    TimeoutType::Long => println!(
                        "Long timeout is {}",
                        format_duration(cfg.get_long_timeout())
                    ),
                },
            }
            Ok(())
        }
    }
    mod ldap {
        use crate::config::Config;
        use crate::proto::ldap::Session;
        use crate::run::config::lookup_host;
        use anyhow::Context;
        use clap::{Args, Subcommand};
        use ldap3::SearchEntry;
        #[derive(Args)]
        pub struct LdapCommand {
            pub host: String,
            # [arg (short , long , default_value = None)]
            pub user: Option<String>,
            # [arg (short , long , default_value = None)]
            pub pass: Option<String>,
            # [arg (short , long , default_value = None)]
            pub domain: Option<String>,
            #[command(subcommand)]
            pub cmd: LdapCommandEnum,
        }
        #[derive(Subcommand)]
        pub enum LdapCommandEnum {
            Test,
            Users,
            Search(SearchCommand),
        }
        pub async fn ldap(cmd: LdapCommand, cfg: &mut Config) -> anyhow::Result<()> {
            let host = lookup_host(cfg, &cmd.host)?;
            let domain = cmd
                .domain
                .or_else(|| {
                    host.aliases
                        .iter()
                        .map(|alias| alias.splitn(2, ".").collect::<Vec<_>>())
                        .filter_map(|alias| {
                            if alias.len() == 2 {
                                Some(alias[1].to_owned())
                            } else {
                                None
                            }
                        })
                        .next()
                })
                .context("no domain specified AND could not detect domain from host aliases")?;
            let user = cmd.user.as_ref().unwrap_or_else(|| &host.user);
            let pass: &str = cmd
                .pass
                .as_ref()
                .or_else(|| host.pass.as_ref())
                .context("no pass specified AND host does not have a password set")?;
            let session = tokio::time::timeout(
                cfg.get_short_timeout(),
                Session::new(host.ip, &domain, user, pass),
            )
            .await
            .context("ldap connection timed out")?
            .context("ldap connection failed")?;
            match cmd.cmd {
                LdapCommandEnum::Test => {
                    log::info!("LDAP connection succeeded, leaving");
                    Ok(())
                }
                LdapCommandEnum::Users => users(session).await,
                LdapCommandEnum::Search(cmd) => search(cmd, session).await,
            }
        }
        async fn users(mut session: Session) -> anyhow::Result<()> {
            let users = session.users().await?;
            let (admins, users): (Vec<_>, _) = users.into_iter().partition(|user| user.admin);
            log::info!("Admins for {}:", session.domain());
            for admin in admins {
                println!("{:<25} (full name {})", admin.id, admin.name);
            }
            log::info!("Users for {}:", session.domain());
            for user in users {
                println!("{:<25} (full name {})", user.id, user.name);
            }
            Ok(())
        }
        #[derive(Args)]
        pub struct SearchCommand {
            pub container: String,
            #[arg(default_value = "(objectClass=top)")]
            pub filter: String,
            # [arg (default_values_t = ["*" . to_string ()])]
            pub attrs: Vec<String>,
        }
        async fn search(cmd: SearchCommand, mut session: Session) -> anyhow::Result<()> {
            let entries = session
                .search(&cmd.container, &cmd.filter, cmd.attrs)
                .await?;
            for entry in entries {
                let entry = SearchEntry::construct(entry);
                println!("dn: {}", entry.dn);
                for (key, vals) in entry.attrs {
                    for val in vals {
                        println!("{}: {}", key, val);
                    }
                }
                println!("");
            }
            Ok(())
        }
    }
    mod profile {
        use crate::config::{Config, Host};
        use crate::proto::{ldap::Session as LdapSession, rdp, ssh::Session as SshSession};
        use crate::run::script::{RunScriptArgs, run_script_all};
        use crate::scan::OsType;
        use crate::util::ip::convert_to_cidr;
        use anyhow::Context;
        use cidr::IpCidr;
        use clap::{Args, ValueEnum};
        use hickory_resolver::TokioAsyncResolver;
        use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
        use std::collections::HashSet;
        use std::path::PathBuf;
        use std::time::Duration;
        use tokio::task::JoinSet;
        #[derive(ValueEnum, Clone, PartialEq, Eq, PartialOrd, Ord)]
        pub enum ProfileStrategy {
            Rdp,
            Ssh,
            Hostname,
            Ldap,
        }
        #[derive(Args)]
        pub struct ProfileCommand {
            pub strategies: Option<Vec<ProfileStrategy>>,
        }
        pub async fn profile(cmd: ProfileCommand, cfg: &mut Config) -> anyhow::Result<()> {
            let mut strategies = cmd.strategies.unwrap_or_else(|| {
                log::info!("No strategy picked, setting all");
                vec![
                    ProfileStrategy::Rdp,
                    ProfileStrategy::Ssh,
                    ProfileStrategy::Hostname,
                    ProfileStrategy::Ldap,
                ]
            });
            strategies.sort();
            for strat in strategies {
                match strat {
                    ProfileStrategy::Rdp => rdp(cfg).await?,
                    ProfileStrategy::Ssh => ssh(cfg).await?,
                    ProfileStrategy::Hostname => hostname(cfg).await?,
                    ProfileStrategy::Ldap => ldap(cfg).await?,
                }
            }
            Ok(())
        }
        pub async fn rdp(cfg: &mut Config) -> anyhow::Result<()> {
            let timeout = cfg.get_short_timeout();
            let mut set = JoinSet::new();
            for (_, host) in cfg
                .hosts()
                .iter()
                .filter(|(_, host)| host.open_ports.contains(&3389))
            {
                let host = host.clone();
                set.spawn(
                    async move { (host.clone(), rdp::grab_rdp_hostname(host.ip, timeout).await) },
                );
            }
            while let Some(joined) = set.join_next().await {
                let (mut host, result) = joined.context("Error running rdp command")?;
                match result {
                    Ok(name) => {
                        log::info!("Got name {} for host {}", name, host);
                        host.aliases.insert(name);
                        cfg.add_host(&host);
                    }
                    Err(err) => {
                        log::error!("Failed to get rdp hostname for host {}: {}", host, err);
                    }
                }
            }
            Ok(())
        }
        pub async fn do_ssh(host: &Host, timeout: Duration) -> anyhow::Result<(String, OsType)> {
            let id = SshSession::get_server_id((host.ip, host.port), timeout).await?;
            let os = if id.to_lowercase().contains("windows") {
                OsType::Windows
            } else {
                OsType::UnixLike
            };
            Ok((id, os))
        }
        pub async fn ssh(cfg: &mut Config) -> anyhow::Result<()> {
            let mut set = JoinSet::new();
            for (_, host) in cfg.hosts() {
                let host = host.clone();
                let timeout = cfg.get_short_timeout();
                set.spawn(async move { (host.clone(), do_ssh(&host, timeout).await) });
            }
            while let Some(joined) = set.join_next().await {
                let (mut host, result) = joined.context("Failed to spawn host ID detector")?;
                match result {
                    Ok((id, os)) => {
                        log::info!("Got ssh ID {} for host {}", id.trim(), host);
                        host.desc.insert(id.trim().to_string());
                        match os {
                            OsType::UnixLike => {
                                host.os = OsType::UnixLike;
                                host.user = cfg.linux_root().into();
                            }
                            OsType::Windows => {
                                host.os = OsType::Windows;
                                host.user = cfg.windows_root().into();
                            }
                        }
                        if os != host.os {
                            host.os = os;
                        }
                        cfg.add_host(&host);
                    }
                    Err(err) => {
                        log::error!("Failed to detect ssh ID for host {}: {}", host, err);
                    }
                }
            }
            Ok(())
        }
        pub async fn hostname(cfg: &mut Config) -> anyhow::Result<()> {
            let script = PathBuf::from("hostname.sh");
            let mut set = run_script_all(
                cfg.get_short_timeout().max(Duration::from_secs(2)),
                cfg,
                RunScriptArgs::new(script),
            )
            .await;
            while let Some(joined) = set.join_next().await {
                let (mut host, result) = joined.context("Error running hostname script")?;
                match result {
                    Ok((code, output)) => {
                        log::warn!(
                            "Hostname script returned nonzero code {} for host {}",
                            code,
                            host
                        );
                        let alias = output.trim();
                        log::info!("Got alias {} for host {}", alias, host);
                        host.aliases.insert(alias.into());
                        cfg.add_host(&host);
                    }
                    Err(err) => {
                        log::error!("Error running script on host {}: {}", host, err);
                    }
                }
            }
            Ok(())
        }
        fn get_domains(cfg: &Config) -> HashSet<String> {
            cfg.hosts()
                .iter()
                .flat_map(|(_, host)| {
                    host.aliases
                        .iter()
                        .map(|alias| alias.splitn(2, '.').collect::<Vec<_>>())
                })
                .filter_map(|alias| {
                    if alias.len() == 2 {
                        Some(alias[1].to_owned())
                    } else {
                        None
                    }
                })
                .collect()
        }
        async fn lookup_domain_on<'a>(
            host: &Host,
            dns: &TokioAsyncResolver,
            domains: &'a HashSet<String>,
            cidr: &IpCidr,
        ) -> Option<&'a str> {
            for domain in domains {
                let ips = dns.lookup_ip(domain).await;
                let found = ips
                    .map(|ips| {
                        ips.iter()
                            .filter_map(|ip| convert_to_cidr(*cidr, ip).ok())
                            .filter(|ip| ip == &host.ip)
                            .next()
                    })
                    .ok()
                    .flatten();
                if found.is_some() {
                    return Some(domain.as_str());
                }
            }
            None
        }
        async fn do_ldap(
            dc: &Host,
            domain: &str,
            cidr: IpCidr,
            cfg: &mut Config,
        ) -> anyhow::Result<()> {
            if let Some(pass) = &dc.pass {
                let mut dc = dc.clone();
                dc.desc.insert(format!("Domain controller for {}", domain));
                cfg.add_host(&dc);
                let timeout = cfg.get_short_timeout();
                let mut session =
                    tokio::time::timeout(timeout, LdapSession::new(dc.ip, domain, &dc.user, pass))
                        .await
                        .context("ldap connection timed out")?
                        .context("error connecting to ldap")?;
                let mut config = ResolverConfig::new();
                config.add_name_server(NameServerConfig::new((dc.ip, 53).into(), Protocol::Tcp));
                config.set_domain(
                    format!("{}.", domain)
                        .parse()
                        .context("domain has invalid format for DNS resolver")?,
                );
                let mut opts = ResolverOpts::default();
                opts.timeout = timeout;
                opts.attempts = 2;
                let dns = TokioAsyncResolver::tokio(config, opts);
                for computer in session.computers().await? {
                    let host = dns
                        .lookup_ip(computer.dns_name.clone())
                        .await
                        .ok()
                        .and_then(|ips| ips.iter().next())
                        .and_then(|ip| {
                            log::info!("Computer {} has ip {}", computer.name, ip);
                            convert_to_cidr(cidr, ip).ok()
                        })
                        .and_then(|ip| cfg.host_for_ip(ip));
                    match host {
                        Some(host) => {
                            let mut host = host.clone();
                            host.aliases.insert(computer.name);
                            host.aliases.insert(computer.dns_name);
                            if let Some(os) = computer.os {
                                log::info!("Host {} has OS {}", host, os);
                                if os.to_lowercase().contains("windows") {
                                    host.os = OsType::Windows;
                                    host.user = cfg.windows_root().into();
                                } else if os.to_lowercase().contains("linux") {
                                    host.os = OsType::UnixLike;
                                    host.user = cfg.linux_root().into();
                                }
                                host.desc.insert(
                                    format!("{} {}", os, computer.os_version.unwrap_or("".into()))
                                        .trim()
                                        .to_string(),
                                );
                            }
                            cfg.add_host(&host);
                        }
                        None => {
                            log::warn!("No host found for hostname {} in domain", computer.name)
                        }
                    }
                }
                Ok(())
            } else {
                anyhow::bail!("Detected domain for DC {}, but no password!", dc.ip);
            }
        }
        pub async fn ldap(cfg: &mut Config) -> anyhow::Result<()> {
            let cidr = cfg
                .get_cidr()
                .context("no cidr set; have you run a scan?")?;
            let domains = get_domains(cfg);
            log::info!("Found domains {:?}", domains);
            let servers: Vec<_> = cfg
                .hosts()
                .iter()
                .filter(|(_, host)| host.open_ports.contains(&53))
                .map(|(_, host)| {
                    log::debug!("Adding DNS server {}", host);
                    let mut config = ResolverConfig::new();
                    config.add_name_server(NameServerConfig::new(
                        (host.ip.clone(), 53).into(),
                        Protocol::Tcp,
                    ));
                    (
                        host.clone(),
                        TokioAsyncResolver::tokio(config, Default::default()),
                    )
                })
                .collect();
            let timeout = cfg.get_short_timeout();
            for (host, server) in servers {
                match tokio::time::timeout(
                    timeout,
                    lookup_domain_on(&host, &server, &domains, &cidr),
                )
                .await
                {
                    Ok(result) => match result {
                        Some(domain) => {
                            log::info!("Found domain {} for host {}", domain, host);
                            if let Err(err) = do_ldap(&host, domain, cidr, cfg).await {
                                log::warn!("Error while running LDAP for DC {}: {}", host, err);
                            }
                        }
                        None => log::debug!("No domain matched for DNS server {}", host),
                    },
                    Err(_) => log::debug!("DNS connection timed out for host {}", host),
                }
            }
            Ok(())
        }
    }
    mod scan {
        use crate::config::Config;
        use crate::run::config::lookup_host;
        use crate::scan::{Backend, OsType, Scan};
        use crate::util::strings::comma_join;
        use cidr::IpCidr;
        use clap::Args;
        #[derive(Args)]
        pub struct ScanCommand {
            pub subnet: IpCidr,
            #[arg(short, long)]
            pub linux_root: Option<String>,
            #[arg(short, long)]
            pub windows_root: Option<String>,
            pub pass: String,
            #[arg(short, long, default_value_t = 22)]
            pub port: u16,
            # [arg (short , long , default_value_t = Backend :: RustScan)]
            pub backend: Backend,
        }
        pub async fn scan(cmd: ScanCommand, cfg: &mut Config) -> anyhow::Result<()> {
            log::debug!("Subnet: {:?}", cmd.subnet);
            cfg.set_cidr(cmd.subnet);
            let scan = Scan::new(
                &cmd.subnet,
                &Scan::common_ports(),
                cmd.backend,
                cfg.get_short_timeout(),
            )
            .await?;
            let linux_root = cmd.linux_root.unwrap_or(cfg.linux_root().into());
            let windows_root = cmd.windows_root.unwrap_or(cfg.windows_root().into());
            for host in scan.hosts {
                let user = match host.os {
                    OsType::UnixLike => &linux_root,
                    OsType::Windows => &windows_root,
                }
                .clone();
                log::info!(
                    "Found host {} with os {:?}, ports: {}",
                    host.addr,
                    host.os,
                    comma_join(&host.ports)
                );
                cfg.add_host_from(&host, user, Some(cmd.pass.clone()), cmd.port)?;
            }
            Ok(())
        }
        #[derive(Args)]
        pub struct RescanCommand {
            pub host: String,
            pub ports: Option<Vec<u16>>,
            # [arg (short , long , default_value_t = Backend :: RustScan)]
            pub backend: Backend,
        }
        pub async fn rescan(cmd: RescanCommand, cfg: &mut Config) -> anyhow::Result<()> {
            let mut host = lookup_host(cfg, &cmd.host)?.clone();
            let mut ports = Scan::common_ports();
            ports.extend(cmd.ports.unwrap_or(Vec::new()));
            log::debug!("Rescanning for host {}", host);
            let scan = Scan::new(
                &IpCidr::new_host(host.ip),
                &ports,
                cmd.backend,
                cfg.get_short_timeout(),
            )
            .await?;
            if scan.hosts.len() == 0 {
                anyhow::bail!("No hosts scanned; is the host up?");
            }
            let scanned = &scan.hosts[0];
            log::info!("Got ports {}", comma_join(&scanned.ports));
            host.open_ports = scanned.ports.clone();
            cfg.add_host(&host);
            Ok(())
        }
        #[derive(Args)]
        pub struct PortCheckCommand {
            pub host: String,
            #[arg(required = true)]
            pub ports: Vec<u16>,
            # [arg (short , long , default_value_t = Backend :: RustScan)]
            pub backend: Backend,
        }
        pub async fn port_check(cmd: PortCheckCommand, cfg: &mut Config) -> anyhow::Result<()> {
            let host = lookup_host(cfg, &cmd.host)?;
            let scan = Scan::new(
                &IpCidr::new_host(host.ip),
                &cmd.ports,
                cmd.backend,
                cfg.get_short_timeout(),
            )
            .await?;
            if scan.hosts.len() == 0 {
                anyhow::bail!("No hosts scanned; is the host up?");
            }
            let scanned = &scan.hosts[0];
            let (open, closed): (Vec<u16>, _) = cmd
                .ports
                .iter()
                .partition(|port| scanned.ports.contains(port));
            log::info!("Open   ports: {}", comma_join(open));
            log::info!("Closed ports: {}", comma_join(closed));
            Ok(())
        }
    }
    pub mod script {
        use crate::config::{Config, Host};
        use crate::proto::ssh::Session;
        use crate::run::config::lookup_host;
        use anyhow::Context;
        use clap::Args;
        use std::path::{Path, PathBuf};
        use std::time::Duration;
        use tokio::task::JoinSet;
        #[derive(Clone)]
        pub struct RunScriptArgs {
            script: PathBuf,
            args: Vec<String>,
            upload: bool,
        }
        impl RunScriptArgs {
            pub fn new(script: PathBuf) -> Self {
                Self {
                    script: script,
                    args: Vec::new(),
                    upload: false,
                }
            }
            pub fn set_upload(mut self, upload: bool) -> Self {
                self.upload = upload;
                self
            }
            pub fn set_args(mut self, args: Vec<String>) -> Self {
                self.args = args;
                self
            }
        }
        async fn do_run_script_args(
            host: &Host,
            args: RunScriptArgs,
        ) -> anyhow::Result<(u32, String)> {
            if let Some(pass) = &host.pass {
                let mut session = Session::connect(&host.user, pass, (host.ip, host.port)).await?;
                let (code, output) = session
                    .run_script(&args.script, args.args, true, args.upload)
                    .await?;
                let output = String::from_utf8_lossy(&output);
                Ok((code, output.into()))
            } else {
                anyhow::bail!("No password for host set")
            }
        }
        pub async fn run_script_args(
            timeout: Duration,
            host: &Host,
            args: RunScriptArgs,
        ) -> anyhow::Result<(u32, String)> {
            tokio::time::timeout(timeout, do_run_script_args(host, args))
                .await
                .unwrap_or_else(|_| Err(anyhow::Error::msg("run_script_args timed out")))
        }
        pub async fn run_script(
            timeout: Duration,
            host: &Host,
            args: RunScriptArgs,
        ) -> anyhow::Result<(u32, String)> {
            run_script_args(timeout, host, args).await
        }
        pub async fn run_script_all_args<F: FnMut(&Host) -> Vec<String>>(
            timeout: Duration,
            cfg: &Config,
            mut gen_args: F,
            args: RunScriptArgs,
        ) -> JoinSet<(Host, anyhow::Result<(u32, String)>)> {
            log::info!("Executing script on all hosts");
            let mut set = JoinSet::new();
            for (_, host) in cfg.script_hosts() {
                let host = host.clone();
                let mut args = args.clone();
                args.args = gen_args(&host);
                set.spawn(async move {
                    (
                        host.clone(),
                        run_script_args(timeout, &host, args.clone()).await,
                    )
                });
            }
            set
        }
        pub async fn run_script_all(
            timeout: Duration,
            cfg: &Config,
            args: RunScriptArgs,
        ) -> JoinSet<(Host, anyhow::Result<(u32, String)>)> {
            let arg_list = args.args.clone();
            run_script_all_args(timeout, cfg, |_| arg_list.clone(), args).await
        }
        async fn do_upload_script(host: &Host, script: &Path) -> anyhow::Result<()> {
            if let Some(pass) = &host.pass {
                let mut session = Session::connect(&host.user, pass, (host.ip, host.port)).await?;
                session.upload(script).await?;
                Ok(())
            } else {
                anyhow::bail!("No password for host set")
            }
        }
        async fn upload_script(
            timeout: Duration,
            host: &Host,
            script: &Path,
        ) -> anyhow::Result<()> {
            tokio::time::timeout(timeout, do_upload_script(host, script))
                .await
                .unwrap_or_else(|_| Err(anyhow::Error::msg("run_script_args timed out")))
        }
        pub async fn upload_script_all(
            timeout: Duration,
            cfg: &Config,
            script: &Path,
        ) -> JoinSet<(Host, anyhow::Result<()>)> {
            let mut set = JoinSet::new();
            for (_, host) in cfg.script_hosts() {
                let host = host.clone();
                let script = script.to_owned();
                set.spawn(
                    async move { (host.clone(), upload_script(timeout, &host, &script).await) },
                );
            }
            set
        }
        #[derive(Args)]
        pub struct ScriptCommand {
            pub script: PathBuf,
            #[arg(short('H'), long)]
            pub host: Option<String>,
            #[arg(short, long, default_value_t = false)]
            pub upload: bool,
            pub args: Vec<String>,
        }
        pub async fn script(cmd: ScriptCommand, cfg: &mut Config) -> anyhow::Result<()> {
            match cmd.host {
                Some(host) => {
                    let host = lookup_host(&cfg, &host)?;
                    log::info!("Running script on host {}", host);
                    let (code, output) = run_script(
                        cfg.get_long_timeout(),
                        host,
                        RunScriptArgs::new(cmd.script).set_upload(cmd.upload),
                    )
                    .await?;
                    log::info!("Script exited with code {}. Output: {}", code, output);
                }
                None => {
                    let mut set = run_script_all(
                        cfg.get_long_timeout(),
                        cfg,
                        RunScriptArgs::new(cmd.script)
                            .set_upload(cmd.upload)
                            .set_args(cmd.args),
                    )
                    .await;
                    while let Some(joined) = set.join_next().await {
                        joined.context("Error running script").map(
                            |(host, result)| match result {
                                Ok((code, output)) => {
                                    log::info!(
                                        "Script on host {} returned code {} with output: {}",
                                        host,
                                        code,
                                        output
                                    );
                                }
                                Err(err) => {
                                    log::error!("Error running script on host {}: {}", host, err);
                                }
                            },
                        )?;
                    }
                }
            }
            Ok(())
        }
        #[derive(Args)]
        pub struct ShellCommand {
            pub host: String,
        }
        pub async fn shell(cmd: ShellCommand, cfg: &mut Config) -> anyhow::Result<()> {
            let host = lookup_host(cfg, &cmd.host)?;
            if let Some(pass) = &host.pass {
                let mut session = Session::connect(&host.user, &pass, (host.ip, host.port)).await?;
                log::info!("ssh {}@{} -p {}", host.user, host, host.port);
                log::info!("Using password '{}'", &pass);
                let code = session.shell().await?;
                if code != 0 {
                    log::warn!("Shell returned nonzero code {}", code);
                }
            } else {
                log::error!("Host does not have a password set! Please set it first.");
            }
            Ok(())
        }
        #[derive(Args)]
        pub struct UploadCommand {
            pub file: PathBuf,
            pub host: Option<String>,
        }
        pub async fn upload(cmd: UploadCommand, cfg: &mut Config) -> anyhow::Result<()> {
            let timeout = cfg.get_long_timeout();
            match cmd.host {
                Some(host) => {
                    let host = lookup_host(cfg, &host)?;
                    upload_script(timeout, host, &cmd.file).await
                }
                None => {
                    let mut set = upload_script_all(timeout, cfg, &cmd.file).await;
                    while let Some(joined) = set.join_next().await {
                        let (host, result) = joined.context("Failed to run upload command")?;
                        match result {
                            Ok(()) => {
                                log::info!("Successfully uploaded script to host {}", host);
                            }
                            Err(err) => {
                                log::error!("Failed to upload script on host {}: {}", host, err);
                            }
                        }
                    }
                    Ok(())
                }
            }
        }
        async fn run_base_script_args(
            cfg: &mut Config,
            name: &str,
            args: Vec<String>,
        ) -> anyhow::Result<()> {
            script(
                ScriptCommand {
                    script: PathBuf::from(format!("{}.sh", name)),
                    host: None,
                    upload: false,
                    args,
                },
                cfg,
            )
            .await
        }
        async fn run_base_script(cfg: &mut Config, name: &str) -> anyhow::Result<()> {
            run_base_script_args(cfg, name, vec![]).await
        }
        pub async fn base(_cmd: (), cfg: &mut Config) -> anyhow::Result<()> {
            log::info!("Running hardening scripts");
            run_base_script(cfg, "php").await?;
            run_base_script(cfg, "ssh").await?;
            run_base_script(cfg, "lockdown").await?;
            upload(
                UploadCommand {
                    file: PathBuf::from("firewall_template.sh"),
                    host: None,
                },
                cfg,
            )
            .await?;
            run_base_script_args(cfg, "initial_backup", vec!["/etc/backup".into()]).await?;
            run_base_script(cfg, "ident").await?;
            Ok(())
        }
    }
    #[derive(Parser)]
    pub enum BlazeCommand {
        Scan(scan::ScanCommand),
        Rescan(scan::RescanCommand),
        #[clap(alias = "pc")]
        PortCheck(scan::PortCheckCommand),
        #[clap(alias = "a")]
        Add(config::AddCommand),
        #[clap(alias = "rm")]
        Remove(config::RemoveCommand),
        #[clap(alias = "ls")]
        List(config::ListCommand),
        #[clap(alias = "i")]
        Info(config::InfoCommand),
        #[clap(alias = "tm")]
        Timeout(config::TimeoutCommand),
        Export(config::ExportCommand),
        Import(config::ImportCommand),
        #[clap(alias = "e")]
        Edit(config::EditCommand),
        Exclude(config::ExcludeCommand),
        #[clap(alias = "r")]
        Chpass,
        #[clap(alias = "sc")]
        Script(script::ScriptCommand),
        Base,
        #[clap(alias = "sh")]
        Shell(script::ShellCommand),
        #[clap(alias = "up")]
        Upload(script::UploadCommand),
        #[clap(alias = "pr")]
        Profile(profile::ProfileCommand),
        Ldap(ldap::LdapCommand),
    }
    pub async fn run(cmd: BlazeCommand, cfg: &mut Config) -> anyhow::Result<()> {
        match cmd {
            BlazeCommand::Scan(cmd) => scan::scan(cmd, cfg).await?,
            BlazeCommand::Rescan(cmd) => scan::rescan(cmd, cfg).await?,
            BlazeCommand::PortCheck(cmd) => scan::port_check(cmd, cfg).await?,
            BlazeCommand::Add(cmd) => config::add_host(cmd, cfg).await?,
            BlazeCommand::Remove(cmd) => config::remove_host(cmd, cfg).await?,
            BlazeCommand::List(cmd) => config::list_hosts(cmd, cfg).await?,
            BlazeCommand::Info(cmd) => config::host_info(cmd, cfg).await?,
            BlazeCommand::Timeout(cmd) => config::set_timeout(cmd, cfg).await?,
            BlazeCommand::Export(cmd) => config::export(cmd, cfg).await?,
            BlazeCommand::Import(cmd) => config::import(cmd, cfg).await?,
            BlazeCommand::Exclude(cmd) => config::exclude(cmd, cfg).await?,
            BlazeCommand::Chpass => chpass::chpass((), cfg).await?,
            BlazeCommand::Script(cmd) => script::script(cmd, cfg).await?,
            BlazeCommand::Base => script::base((), cfg).await?,
            BlazeCommand::Shell(cmd) => script::shell(cmd, cfg).await?,
            BlazeCommand::Upload(cmd) => script::upload(cmd, cfg).await?,
            BlazeCommand::Edit(cmd) => config::edit_host(cmd, cfg).await?,
            BlazeCommand::Profile(cmd) => profile::profile(cmd, cfg).await?,
            BlazeCommand::Ldap(cmd) => ldap::ldap(cmd, cfg).await?,
        }
        Ok(())
    }
}
mod scan {
    use crate::util::strings::join;
    use anyhow::Context;
    use cidr::IpCidr;
    use clap::ValueEnum;
    use nmap_xml_parser::{
        NmapResults,
        host::{Address, Host as NmapHost},
    };
    use rustscan::input::ScanOrder;
    use rustscan::port_strategy::PortStrategy;
    use rustscan::scanner::Scanner;
    use serde::{Deserialize, Serialize};
    use std::{
        collections::{HashMap, HashSet},
        fmt::{Display, Formatter},
        net::IpAddr,
        process::Stdio,
        time::Duration,
    };
    use tokio::{fs::read_to_string, process::Command};
    #[derive(Clone, Debug)]
    pub struct Scan {
        pub hosts: Vec<Host>,
    }
    #[derive(Serialize, Deserialize, Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
    pub enum OsType {
        #[value(alias("unix"))]
        UnixLike,
        #[value(alias("win"))]
        Windows,
    }
    #[derive(Clone, Debug)]
    pub struct Host {
        pub addr: IpAddr,
        pub ports: HashSet<u16>,
        pub os: OsType,
    }
    impl Host {
        pub fn new(addr: IpAddr, ports: HashSet<u16>) -> Host {
            let os = if ports.iter().any(|port| port == &3389) {
                OsType::Windows
            } else {
                OsType::UnixLike
            };
            Host { addr, ports, os }
        }
    }
    impl TryFrom<&NmapHost> for Host {
        type Error = anyhow::Error;
        fn try_from(nmap: &NmapHost) -> anyhow::Result<Self> {
            let addr = nmap
                .addresses()
                .filter_map(|addr| match addr {
                    Address::IpAddr(addr) => Some(addr),
                    _ => None,
                })
                .next()
                .ok_or_else(|| anyhow::Error::msg("no IP addresses for nmap host"))?;
            let ports: HashSet<u16> = nmap
                .port_info
                .ports()
                .map(|port| port.port_number)
                .collect();
            Ok(Host::new(addr.clone(), ports))
        }
    }
    #[derive(Clone, Debug, ValueEnum)]
    pub enum Backend {
        Nmap,
        RustScan,
    }
    impl Display for Backend {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            let str = match self {
                Backend::Nmap => "nmap",
                Backend::RustScan => "rust-scan",
            };
            f.write_str(str)
        }
    }
    impl Scan {
        async fn nmap(subnet: &IpCidr, ports: &Vec<u16>) -> anyhow::Result<Vec<Host>> {
            let ports_arg = join(ports, ",");
            let args = vec![
                "--min-rate",
                "3000",
                "-p",
                &ports_arg,
                "--open",
                "-oX",
                "scan.xml",
                subnet.to_string().leak(),
            ];
            let result = Command::new("nmap")
                .args(args)
                .stdout(Stdio::null())
                .status()
                .await
                .context("nmap failed to spawn")?
                .success();
            if result == false {
                anyhow::bail!("nmap failed to execute");
            }
            let file = read_to_string("scan.xml")
                .await
                .context("nmap output file not readable")?;
            let scan = NmapResults::parse(&file).context("nmap output file not parseable")?;
            Ok(scan
                .hosts()
                .filter_map(|host| host.try_into().ok())
                .collect())
        }
        async fn rustscan(
            subnet: &IpCidr,
            ports: &Vec<u16>,
            timeout: Duration,
        ) -> anyhow::Result<Vec<Host>> {
            let ips: Vec<IpAddr> = subnet.iter().map(|c| c.address()).collect();
            let strategy = PortStrategy::pick(&None, Some(ports.clone()), ScanOrder::Serial);
            let scanner = Scanner::new(&ips, 100, timeout, 1, true, strategy, true, vec![], false);
            log::info!(
                "rustscan -a {} -g -t {} -p {}",
                subnet,
                timeout.as_millis(),
                join(ports, ",")
            );
            let mut hosts = HashMap::<IpAddr, HashSet<u16>>::new();
            scanner.run().await.iter().for_each(|addr| {
                let ip = addr.ip();
                hosts
                    .entry(ip)
                    .or_insert(HashSet::new())
                    .insert(addr.port());
            });
            Ok(hosts
                .into_iter()
                .map(|(addr, ports)| Host::new(addr, ports))
                .collect())
        }
        pub fn common_ports() -> Vec<u16> {
            vec![
                22, 3389, 88, 135, 389, 445, 5985, 3306, 5432, 27017, 53, 80, 443, 8080,
            ]
        }
        pub async fn new(
            subnet: &IpCidr,
            ports: &Vec<u16>,
            backend: Backend,
            timeout: Duration,
        ) -> anyhow::Result<Scan> {
            Ok(Scan {
                hosts: match backend {
                    Backend::Nmap => Scan::nmap(subnet, ports).await?,
                    Backend::RustScan => Scan::rustscan(subnet, ports, timeout).await?,
                },
            })
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[tokio::test]
        async fn test_nmap() -> anyhow::Result<()> {
            Scan::new(
                &"10.100.3.0/24".parse().unwrap(),
                &Scan::common_ports(),
                Backend::Nmap,
                Duration::from_secs(5),
            )
            .await
            .map(|_| ())
        }
        #[tokio::test]
        async fn test_rustscan() -> anyhow::Result<()> {
            Scan::new(
                &"10.100.3.0/24".parse().unwrap(),
                &Scan::common_ports(),
                Backend::RustScan,
                Duration::from_secs(5),
            )
            .await
            .map(|_| ())
        }
    }
}
mod scripts {
    use anyhow::Context;
    use rust_embed::Embed;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use tokio::fs::File;
    use tokio::io;
    #[derive(Embed)]
    #[folder = "scripts/"]
    pub struct Scripts;
    impl Scripts {
        pub fn root() -> PathBuf {
            "scripts/".into()
        }
        async fn create_dir(path: &Path) -> anyhow::Result<bool> {
            let result = tokio::fs::create_dir(path).await;
            if let Err(err) = result {
                if err.kind() == io::ErrorKind::AlreadyExists {
                    log::info!("Directory already exists, skipping unpack step");
                    Ok(true)
                } else {
                    Err(err.into())
                }
            } else {
                Ok(false)
            }
        }
        async fn copy_file(file: &str) -> anyhow::Result<()> {
            let contents =
                Self::get(file).with_context(|| format!("failed to open file {}", file))?;
            let mut path = Self::root();
            path.push(file);
            let mut dst = File::create(path).await?;
            let mut src = Cursor::new(contents.data);
            io::copy(&mut src, &mut dst).await?;
            Ok(())
        }
        pub async fn unpack() -> anyhow::Result<()> {
            let root = Self::root();
            let existed = Self::create_dir(&root).await?;
            if !existed {
                for file in Self::iter() {
                    if let Err(err) = Self::copy_file(&file).await {
                        log::warn!("Failed to copy file {}: {}", file, err);
                    }
                }
            }
            Ok(())
        }
        pub async fn find(file: &Path) -> Option<File> {
            let mut path = Self::root();
            path.push(file);
            File::open(path).await.ok()
        }
    }
}
mod util {
    pub mod ip {
        use cidr::IpCidr;
        use std::net::IpAddr;
        pub fn convert_to_cidr(cidr: IpCidr, ip: IpAddr) -> anyhow::Result<IpAddr> {
            match cidr {
                IpCidr::V4(cidr) => match ip {
                    IpAddr::V4(ip) => {
                        let mask = cidr.mask();
                        Ok(IpAddr::V4(mask & cidr.first_address() | (!mask & ip)))
                    }
                    IpAddr::V6(_) => {
                        anyhow::bail!("Passed IPv4 CIDR and IPv6 IP");
                    }
                },
                IpCidr::V6(cidr) => match ip {
                    IpAddr::V4(_) => {
                        anyhow::bail!("Passed IPv6 CIDR and IPv4 IP");
                    }
                    IpAddr::V6(ip) => {
                        let mask = cidr.mask();
                        Ok(IpAddr::V6((mask & cidr.first_address()) | (!mask & ip)))
                    }
                },
            }
        }
    }
    pub mod strings {
        pub fn join(container: impl IntoIterator<Item = impl ToString>, sep: &str) -> String {
            container
                .into_iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .join(sep)
        }
        pub fn comma_join(container: impl IntoIterator<Item = impl ToString>) -> String {
            join(container, ", ")
        }
    }
}
use clap::Parser;
use config::Config;
use log::LevelFilter;
use repl::repl;
use run::{BlazeCommand, run};
use scripts::Scripts;
use std::path::PathBuf;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .parse_default_env()
        .format_timestamp(None)
        .filter_module("blaze", LevelFilter::Debug)
        .init();
    let mut cfg = Config::from(&PathBuf::from("blaze.yaml")).unwrap_or_else(|err| {
        log::info!("Error loading config: {:?}, loading default", err);
        Config::new()
    });
    Scripts::unpack().await.unwrap_or_else(|err| {
        log::warn!("Error unpacking scripts: {}, continuing", err);
    });
    let command = BlazeCommand::try_parse();
    match command {
        Err(_) => repl(&mut cfg).await?,
        Ok(command) => run(command, &mut cfg).await?,
    }
    Ok(())
}
