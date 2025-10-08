Name:           restic-scheduler
Version:        0.1.0
Release:        1%{?dist}
Summary:        Automatic restic backup scheduler

License:        GPL-3.0-only
URL:            https://github.com/antedebaas/restic-scheduler
Source0:        https://github.com/antedebaas/restic-scheduler/archive/v%{version}/restic-scheduler-%{version}.tar.gz

BuildRequires:  rust >= 1.70
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  openssl-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  pkgconfig(openssl)
BuildRequires:  make

# Only build on supported architectures for Rust
ExcludeArch:    i686 s390 %{power64}

# For COPR compatibility
%if 0%{?fedora} >= 36 || 0%{?rhel} >= 9
%bcond_without check
%else
%bcond_with check
%endif

%global debug_package %{nil}

Requires:       glibc
Requires:       openssl
Requires:       systemd
Requires:       restic
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Restic Scheduler is an automatic backup scheduler for restic with TOML-based
configuration. It provides a comprehensive solution for automating restic
backups with features including multiple backup profiles, flexible scheduling,
email and webhook notifications, backup statistics logging, repository health
checks, and pre/post backup command execution.

Key features include support for multiple backup profiles with individual
configurations, B2 and S3 backend support with proper credential management,
retention policy management, comprehensive notification system, backup
statistics and logging, repository integrity checks, and systemd integration
for reliable scheduling.

%prep
%autosetup -n restic-scheduler-%{version}

%build
# Set build environment for optimal compilation
export CARGO_TARGET_DIR=%{_builddir}/restic-scheduler-%{version}/target
export RUSTFLAGS="-Ccodegen-units=1 -Clink-dead-code=off"

# Ensure we have a proper Cargo.lock
[ -f Cargo.lock ] || cargo generate-lockfile

# Build with release optimizations
cargo build --release --verbose --locked

%install
# Create directory structure
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/restic-scheduler
install -d %{buildroot}%{_sharedstatedir}/restic-scheduler
install -d %{buildroot}%{_localstatedir}/log/restic-scheduler
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_docdir}/%{name}

# Install binary
install -D -m 755 %{_builddir}/restic-scheduler-%{version}/target/release/restic-scheduler %{buildroot}%{_bindir}/restic-scheduler

# Install systemd service and timer files
install -D -m 644 systemd/restic-backup@.service %{buildroot}%{_unitdir}/restic-backup@.service
install -D -m 644 systemd/restic-backup@.timer %{buildroot}%{_unitdir}/restic-backup@.timer
install -D -m 644 systemd/restic-check@.service %{buildroot}%{_unitdir}/restic-check@.service
install -D -m 644 systemd/restic-check@.timer %{buildroot}%{_unitdir}/restic-check@.timer

# Install example configuration file
install -m 640 config.example.toml %{buildroot}%{_sysconfdir}/restic-scheduler/config.toml

# Install documentation
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/

# Install license file
install -m 644 LICENSE %{buildroot}%{_docdir}/%{name}/

%files
%license %{_docdir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%config(noreplace) %{_sysconfdir}/restic-scheduler/config.toml
%{_bindir}/restic-scheduler
%{_unitdir}/restic-backup@.service
%{_unitdir}/restic-backup@.timer
%{_unitdir}/restic-check@.service
%{_unitdir}/restic-check@.timer
%attr(0750,restic-scheduler,restic-scheduler) %dir %{_sharedstatedir}/restic-scheduler
%attr(0750,restic-scheduler,restic-scheduler) %dir %{_localstatedir}/log/restic-scheduler
%attr(0750,restic-scheduler,restic-scheduler) %dir %{_sysconfdir}/restic-scheduler

%pre
# Create restic-scheduler user and group
getent group restic-scheduler >/dev/null || groupadd -r restic-scheduler
getent passwd restic-scheduler >/dev/null || useradd -r -g restic-scheduler -s /usr/sbin/nologin -M -d %{_sharedstatedir}/restic-scheduler -c "Restic Scheduler Service" restic-scheduler

%post
# Ensure proper ownership of directories
if [ $1 -eq 1 ]; then
    chown -R restic-scheduler:restic-scheduler %{_sharedstatedir}/restic-scheduler %{_localstatedir}/log/restic-scheduler 2>/dev/null || true
    chmod 640 %{_sysconfdir}/restic-scheduler/config.toml 2>/dev/null || true
    chown restic-scheduler:restic-scheduler %{_sysconfdir}/restic-scheduler/config.toml 2>/dev/null || true
fi
%systemd_post restic-backup@.service restic-backup@.timer restic-check@.service restic-check@.timer

%preun
%systemd_preun restic-backup@.service restic-backup@.timer restic-check@.service restic-check@.timer

%postun
%systemd_postun_with_restart restic-backup@.service restic-backup@.timer restic-check@.service restic-check@.timer
# Remove user and group on complete removal
if [ $1 -eq 0 ]; then
    # Clean up data directories on uninstall
    rm -rf %{_sharedstatedir}/restic-scheduler/* 2>/dev/null || true
    rm -rf %{_localstatedir}/log/restic-scheduler/* 2>/dev/null || true
    getent passwd restic-scheduler >/dev/null && userdel restic-scheduler >/dev/null 2>&1 || true
    getent group restic-scheduler >/dev/null && groupdel restic-scheduler >/dev/null 2>&1 || true
fi

%changelog
* Thu Jan 16 2025 Restic Scheduler Contributors <maintainer@example.com> - 0.1.0-1
- Initial RPM package for restic-scheduler
- Automatic backup scheduler
- Support for multiple backup profiles
- Email and webhook notifications
- Backup statistics and logging
- Repository integrity checks
- Systemd integration with service and timer units
