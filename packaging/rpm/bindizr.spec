%global crate bindizr

Name:           %{crate}
Version:        0.1.0~beta.1
Release:        1%{?dist}
Summary:        DNS Synchronization Service for BIND9

License:        Apache-2.0
URL:            https://github.com/kweonminsung/bindizr
# NOTE: The version in the URL and setup macro needs the original hyphenated form.
Source0:        https://github.com/kweonminsung/bindizr/archive/v0.1.0-beta.1/bindizr-0.1.0-beta.1.tar.gz

# Build dependencies for Fedora/CentOS/RHEL
# BuildRequires:  rust
# BuildRequires:  cargo

%description
DNS Synchronization Service for BIND9.
This service allows you to manage BIND9 DNS zones and records through a RESTful API.

%prep
%setup -q -n %{name}-0.1.0-beta.1

%build
# Build the release binary
cargo build --release --locked

%install
rm -rf %{buildroot}

# Install the binary
install -D -m 755 target/release/%{crate} %{buildroot}%{_bindir}/%{crate}

# Install the configuration file
install -d %{buildroot}%{_sysconfdir}/%{crate}
install -p -m 644 tests/fixture/bindizr.conf.toml %{buildroot}%{_sysconfdir}/%{crate}/bindizr.conf.toml

# Install the documentation
install -d %{buildroot}%{_docdir}/%{crate}
install -p -m 644 README.md %{buildroot}%{_docdir}/%{crate}/README.md

# Install the license file
install -d %{buildroot}%{_licensedir}/%{crate}
install -p -m 644 LICENSE %{buildroot}%{_licensedir}/%{crate}/LICENSE

%files
%license LICENSE
%doc README.md
%{_bindir}/%{crate}
%config(noreplace) %{_sysconfdir}/%{crate}/bindizr.conf.toml

%changelog
* Tue Sep 09 2025 Minsung Kweon <kevin136583@gmail.com> - 0.1.0~beta.1-1
- Initial RPM packaging
