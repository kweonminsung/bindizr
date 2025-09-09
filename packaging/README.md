# Packaging Bindizr

This document provides instructions for building Debian and RPM packages for Bindizr from the source code.

## Debian Packages (DPKG)

For Debian-based systems (Ubuntu, Debian, etc.), you can build and install Bindizr using the `dpkg-buildpackage` command.

### Prerequisites

- `build-essential`
- `debhelper`
- `rustc`
- `cargo`

```bash
# Install build dependencies
$ sudo apt-get update
$ sudo apt-get install build-essential debhelper rustc cargo
```

### Building the Package

```bash
# Clone the repository
$ git clone https://github.com/kweonminsung/bindizr.git
$ cd bindizr

# The debian packaging scripts expect the 'debian' directory to be at the root.
# We'll create a temporary symlink to it.
$ ln -s packaging/debian .

# Build the Debian package
$ dpkg-buildpackage -us -uc

# Clean up the symlink
$ rm debian

# The generated .deb file will be in the parent directory
$ ls ../bindizr_*.deb
```

### Installing the Package

```bash
# Install the generated .deb file
$ sudo dpkg -i ../bindizr_*.deb
```

## Red Hat Packages (RPM)

For Red Hat-based systems (Fedora, CentOS, RHEL, etc.), you can build and install Bindizr using the `.spec` file.

### Prerequisites

- `rpm-build`
- `rust`
- `cargo`

```bash
# Install build dependencies
$ sudo dnf install rpm-build rust cargo
```

### Building the Package

```bash
# Clone the repository
$ git clone https://github.com/kweonminsung/bindizr.git
$ cd bindizr

# Create the source tarball
$ git archive --format=tar.gz --prefix=bindizr-0.1.0-beta.1/ -o bindizr-0.1.0-beta.1.tar.gz HEAD

# Build the RPM package
$ rpmbuild -ba packaging/rpm/bindizr.spec --define "_sourcedir $(pwd)"

# The generated .rpm file will be in ~/rpmbuild/RPMS/
$ ls ~/rpmbuild/RPMS/x86_64/bindizr-*.rpm
```

### Installing the Package

```bash
# Install the RPM package
$ sudo rpm -i ~/rpmbuild/RPMS/x86_64/bindizr-*.rpm
