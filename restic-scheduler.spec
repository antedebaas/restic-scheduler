Name:           restic-scheduler
Version:        0.2.4
Release:        1%{?dist}
Summary:        Automatic restic backup scheduler

License:        GPL-3.0-only
URL:            https://github.com/antedebaas/%{name}
Source0:        https://github.com/antedebaas/%{name}/archive/v%{version}/%{name}-%{version}.tar.gz

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
Automatic restic backup scheduler for automating backups.
It has support for multiple backup profiles, flexible scheduling,
email, webhook, and command notifications, backup statistics logging,
repository health checks, and pre/post backup command execution.

%prep
%autosetup -n %{name}-%{version}

%build
# Set build environment for optimal compilation
export CARGO_TARGET_DIR=%{_builddir}/%{name}-%{version}/target
export RUSTFLAGS="-Ccodegen-units=1 -Clink-dead-code=off"

# Ensure we have a proper Cargo.lock
[ -f Cargo.lock ] || cargo generate-lockfile

# Build with release optimizations
cargo build --release --verbose --locked

%install
# Create directory structure
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/%{name}
install -d %{buildroot}%{_sharedstatedir}/%{name}
install -d %{buildroot}%{_localstatedir}/log/%{name}
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_docdir}/%{name}
install -d %{buildroot}%{_datadir}/bash-completion/completions

# Install binary
install -D -m 755 %{_builddir}/%{name}-%{version}/target/release/%{name} %{buildroot}%{_bindir}/%{name}

# Install systemd service and timer files
install -D -m 644 systemd/restic-backup@.service %{buildroot}%{_unitdir}/restic-backup@.service
install -D -m 644 systemd/restic-backup@.timer %{buildroot}%{_unitdir}/restic-backup@.timer
install -D -m 644 systemd/restic-check@.service %{buildroot}%{_unitdir}/restic-check@.service
install -D -m 644 systemd/restic-check@.timer %{buildroot}%{_unitdir}/restic-check@.timer

# Install example configuration filerestic-scheduler
install -m 640 config.example.toml %{buildroot}%{_sysconfdir}/%{name}/config.toml

# Install documentation
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/

# Install license file
install -m 644 LICENSE %{buildroot}%{_docdir}/%{name}/

# Install bash completion
install -m 644 bash-completion/restic-scheduler %{buildroot}%{_datadir}/bash-completion/completions/restic-scheduler

%files
%license %{_docdir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%config(noreplace) %{_sysconfdir}/%{name}/config.toml
%{_bindir}/%{name}
%{_unitdir}/restic-backup@.service
%{_unitdir}/restic-backup@.timer
%{_unitdir}/restic-check@.service
%{_unitdir}/restic-check@.timer
%attr(0750,%{name},%{name}) %dir %{_sharedstatedir}/%{name}
%attr(0750,%{name},%{name}) %dir %{_localstatedir}/log/%{name}
%attr(0750,%{name},%{name}) %dir %{_sysconfdir}/%{name}
%{_datadir}/bash-completion/completions/restic-scheduler

%pre
# Create %{name} user and group
getent group %{name} >/dev/null || groupadd -r %{name}
getent group backup >/dev/null || groupadd -r backup
getent passwd %{name} >/dev/null || useradd -r -g %{name} -G backup -s /usr/sbin/nologin -M -d %{_sharedstatedir}/%{name} -c "Restic Scheduler Service" %{name}

%post
# Ensure proper ownership of directories
if [ $1 -eq 1 ]; then
    chown -R %{name}:%{name} %{_sharedstatedir}/%{name} %{_localstatedir}/log/%{name} 2>/dev/null || true
    chmod 640 %{_sysconfdir}/%{name}/config.toml 2>/dev/null || true
    chown %{name}:%{name} %{_sysconfdir}/%{name}/config.toml 2>/dev/null || true
    # Add restic-scheduler user to backup group for privileged access
    usermod -a -G backup %{name} 2>/dev/null || true
fi
# Note: Template units are not enabled by default
# To enable for a specific profile, run:
# systemctl enable restic-backup@PROFILE.timer
# systemctl enable restic-check@PROFILE.timer
systemctl daemon-reload

%preun
# Stop and disable any enabled instances dynamically
for timer in $(systemctl list-unit-files "restic-backup@*.timer" --state=enabled --no-legend 2>/dev/null | awk '{print $1}'); do
    systemctl stop "$timer" 2>/dev/null || true
    systemctl disable "$timer" 2>/dev/null || true
    # Also stop the corresponding service
    service_name="${timer%.timer}.service"
    systemctl stop "$service_name" 2>/dev/null || true
done

for timer in $(systemctl list-unit-files "restic-check@*.timer" --state=enabled --no-legend 2>/dev/null | awk '{print $1}'); do
    systemctl stop "$timer" 2>/dev/null || true
    systemctl disable "$timer" 2>/dev/null || true
    # Also stop the corresponding service
    service_name="${timer%.timer}.service"
    systemctl stop "$service_name" 2>/dev/null || true
done

%postun
systemctl daemon-reload
# Remove user and group on complete removal
if [ $1 -eq 0 ]; then
    # Clean up data directories on uninstallantedebaas@users.github.com> - 0.1.3-1
    rm -rf %{_sharedstatedir}/%{name}/* 2>/dev/null || true
    rm -rf %{_localstatedir}/log/%{name}/* 2>/dev/null || true
    getent passwd %{name} >/dev/null && userdel %{name} >/dev/null 2>&1 || true
    getent group %{name} >/dev/null && groupdel %{name} >/dev/null 2>&1 || true
    # Only remove backup group if no other users depend on it
    if getent group backup >/dev/null && [ $(getent group backup | cut -d: -f4 | tr ',' '\n' | wc -l) -eq 0 ]; then
        groupdel backup >/dev/null 2>&1 || true
    fi
fi

%changelog
* Sun Nov 02 2025 Ante de Baas <antedebaas@users.github.com> - 0.2.4-1
- Some code cleanup
- Improve failure notifications

* Sun Oct 12 2025 Ante de Baas <antedebaas@users.github.com> - 0.2.3-1
- Updated to version 0.2.3

* Fri Oct 10 2025 Ante de Baas <antedebaas@users.github.com> - 0.1.3-1
- Added bash completion file
- removed old logfile implementation.

* Thu Oct 9 2025 Ante de Baas <antedebaas@users.github.com> - 0.1.2-1
- Fixed a bug in matching current process when checking for running instances.

* Wed Oct 8 2025 Ante de Baas <antedebaas@users.github.com> - 0.1.1-1
- Fix Windows build

* Wed Oct 8 2025 Ante de Baas <antedebaas@users.github.com> - 0.1.0-1
- Initial RPM package
