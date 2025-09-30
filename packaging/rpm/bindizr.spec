%global crate bindizr
%global _unitdir /usr/lib/systemd/system

Name:           %{crate}
Version:        0.1.0~beta.2
Release:        1%{?dist}
Summary:        DNS Synchronization Service for BIND9

License:        Apache-2.0
URL:            https://github.com/kweonminsung/bindizr
# NOTE: The version in the URL and setup macro needs the original hyphenated form.
Source0:        https://github.com/kweonminsung/bindizr/archive/v0.1.0-beta.2/bindizr-0.1.0-beta.2.tar.gz

# Build dependencies for Fedora/CentOS/RHEL
# BuildRequires:  rust
# BuildRequires:  cargo
# BuildRequires:  systemd

%description
DNS Synchronization Service for BIND9.
This service allows you to manage BIND9 DNS zones and records through a RESTful API.

%prep
%setup -q -n %{name}-0.1.0-beta.2

%build
# Build the release binary
cargo build --release --locked --target x86_64-unknown-linux-musl

%install
rm -rf %{buildroot}

# Install the binary
install -D -m 755 target/x86_64-unknown-linux-musl/release/%{crate} %{buildroot}%{_bindir}/%{crate}

# Install the configuration file
install -d %{buildroot}%{_sysconfdir}/%{crate}
install -p -m 644 bindizr.conf.toml %{buildroot}%{_sysconfdir}/%{crate}/bindizr.conf.toml

# Install the documentation
install -d %{buildroot}%{_docdir}/%{crate}
install -p -m 644 packaging/rpm/README.md %{buildroot}%{_docdir}/%{crate}/README.md

# Install the license file
install -d %{buildroot}%{_licensedir}/%{crate}
install -p -m 644 LICENSE %{buildroot}%{_licensedir}/%{crate}/LICENSE

# Install systemd service file
install -d %{buildroot}%{_unitdir}
install -p -m 644 packaging/rpm/bindizr.service %{buildroot}%{_unitdir}/bindizr.service

%files
%license %{_licensedir}/%{crate}/LICENSE
%{_unitdir}/bindizr.service
%doc %{_docdir}/%{crate}/README.md
%{_bindir}/%{crate}
%config(noreplace) %{_sysconfdir}/%{crate}/bindizr.conf.toml

%postun
%systemd_postun_with_restart bindizr.service

%changelog
* Tue Sep 30 2025 Minsung Kweon <kevin136583@gmail.com> - 0.1.0~beta.2-1
- Removed fork based daemonization

* Tue Sep 09 2025 Minsung Kweon <kevin136583@gmail.com> - 0.1.0~beta.1-1
- Initial RPM packaging
