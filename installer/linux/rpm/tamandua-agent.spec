%define _name           tamandua-agent
%define _version        %{?version}%{!?version:1.0.0}
%define _release        1%{?dist}
%define _tamandua_user  tamandua
%define _tamandua_group tamandua

Name:           %{_name}
Version:        %{_version}
Release:        %{_release}
Summary:        Tamandua EDR Agent - Endpoint Detection and Response

License:        Apache-2.0
URL:            https://github.com/treant-lab/tamandua-agent
Source0:        %{_name}-%{_version}.tar.gz

BuildRequires:  systemd-rpm-macros

Requires:       glibc >= 2.17
Requires:       openssl-libs >= 1.1
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

# Disable automatic dependency scanning for Rust binary
AutoReqProv:    no

%description
Tamandua EDR Agent provides endpoint detection and response capabilities
for Linux systems.

Features:
- Process and file activity monitoring
- Network connection tracking
- DNS query logging
- Optional eBPF readiness reporting for advanced Linux telemetry
- YARA rule scanning
- Behavioral threat detection
- Automated incident response

%prep
%setup -q -n %{_name}-%{_version}

%build
# Binary is pre-built, no build step needed

%install
# Create directories
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/tamandua
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_sharedstatedir}/tamandua
mkdir -p %{buildroot}%{_sharedstatedir}/tamandua/cache
mkdir -p %{buildroot}%{_sharedstatedir}/tamandua/quarantine
mkdir -p %{buildroot}%{_sharedstatedir}/tamandua/models
mkdir -p %{buildroot}%{_sharedstatedir}/tamandua/rules/yara
mkdir -p %{buildroot}%{_sharedstatedir}/tamandua/rules/sigma
mkdir -p %{buildroot}%{_localstatedir}/log/tamandua
mkdir -p %{buildroot}/run/tamandua

# Install binary
install -m 0755 tamandua-agent %{buildroot}%{_bindir}/tamandua-agent

# Install config
install -m 0640 agent.toml.example %{buildroot}%{_sysconfdir}/tamandua/agent.toml.example

# Install systemd service
install -m 0644 tamandua-agent.service %{buildroot}%{_unitdir}/tamandua-agent.service

# Install feature-based local ML model
install -m 0640 malware_features.onnx %{buildroot}%{_sharedstatedir}/tamandua/models/malware_features.onnx

# Install tmpfiles.d for runtime directory
mkdir -p %{buildroot}%{_tmpfilesdir}
cat > %{buildroot}%{_tmpfilesdir}/tamandua-agent.conf << 'EOF'
d /run/tamandua 0755 tamandua tamandua -
EOF

%pre
# Create tamandua group
getent group %{_tamandua_group} > /dev/null || groupadd -r %{_tamandua_group}

# Create tamandua user
getent passwd %{_tamandua_user} > /dev/null || \
    useradd -r -g %{_tamandua_group} -d %{_sharedstatedir}/tamandua \
    -s /sbin/nologin -c "Tamandua EDR Agent" %{_tamandua_user}

exit 0

%post
%systemd_post tamandua-agent.service

# Set file capabilities
if command -v setcap > /dev/null 2>&1; then
    setcap 'cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search,cap_bpf,cap_perfmon,cap_sys_resource+eip' %{_bindir}/tamandua-agent || true
fi

# Create config from example if not exists
if [ ! -f %{_sysconfdir}/tamandua/agent.toml ]; then
    cp %{_sysconfdir}/tamandua/agent.toml.example %{_sysconfdir}/tamandua/agent.toml
    # Generate unique agent ID
    NEW_UUID=$(cat /proc/sys/kernel/random/uuid)
    sed -i "s/agent_id = \"550e8400-e29b-41d4-a716-446655440001\"/agent_id = \"$NEW_UUID\"/" %{_sysconfdir}/tamandua/agent.toml
    echo "Generated new agent ID: $NEW_UUID"
fi

# Set permissions
chown -R root:%{_tamandua_group} %{_sysconfdir}/tamandua
chmod 750 %{_sysconfdir}/tamandua
chmod 640 %{_sysconfdir}/tamandua/*.toml 2>/dev/null || true
chmod 640 %{_sysconfdir}/tamandua/*.toml.example 2>/dev/null || true

chown -R %{_tamandua_user}:%{_tamandua_group} %{_sharedstatedir}/tamandua
chmod 750 %{_sharedstatedir}/tamandua

chown -R %{_tamandua_user}:%{_tamandua_group} %{_localstatedir}/log/tamandua
chmod 750 %{_localstatedir}/log/tamandua

# Create runtime directory
mkdir -p /run/tamandua
chown %{_tamandua_user}:%{_tamandua_group} /run/tamandua
chmod 755 /run/tamandua

# Enable service on fresh install
if [ $1 -eq 1 ]; then
    systemctl enable tamandua-agent.service
    echo ""
    echo "Tamandua EDR Agent installed successfully!"
    echo ""
    echo "Configuration: %{_sysconfdir}/tamandua/agent.toml"
    echo "Data directory: %{_sharedstatedir}/tamandua"
    echo "Logs: journalctl -u tamandua-agent"
    echo ""
    echo "To start the agent: systemctl start tamandua-agent"
    echo "To check status: systemctl status tamandua-agent"
    echo ""
fi

%preun
%systemd_preun tamandua-agent.service

%postun
%systemd_postun_with_restart tamandua-agent.service

# On complete removal (not upgrade)
if [ $1 -eq 0 ]; then
    # Remove runtime directory
    rm -rf /run/tamandua

    echo "Tamandua agent removed."
    echo "Configuration and data preserved in %{_sysconfdir}/tamandua and %{_sharedstatedir}/tamandua"
    echo "To completely remove all data, run: rm -rf %{_sysconfdir}/tamandua %{_sharedstatedir}/tamandua %{_localstatedir}/log/tamandua"
fi

%files
%license LICENSE
%doc README.md
%attr(0755,root,root) %{_bindir}/tamandua-agent
%dir %attr(0750,root,%{_tamandua_group}) %{_sysconfdir}/tamandua
%config(noreplace) %attr(0640,root,%{_tamandua_group}) %{_sysconfdir}/tamandua/agent.toml.example
%{_unitdir}/tamandua-agent.service
%{_tmpfilesdir}/tamandua-agent.conf
%dir %attr(0750,%{_tamandua_user},%{_tamandua_group}) %{_sharedstatedir}/tamandua
%dir %attr(0750,%{_tamandua_user},%{_tamandua_group}) %{_sharedstatedir}/tamandua/cache
%dir %attr(0750,%{_tamandua_user},%{_tamandua_group}) %{_sharedstatedir}/tamandua/quarantine
%dir %attr(0750,%{_tamandua_user},%{_tamandua_group}) %{_sharedstatedir}/tamandua/models
%attr(0640,%{_tamandua_user},%{_tamandua_group}) %{_sharedstatedir}/tamandua/models/malware_features.onnx
%dir %attr(0750,%{_tamandua_user},%{_tamandua_group}) %{_sharedstatedir}/tamandua/rules
%dir %attr(0750,%{_tamandua_user},%{_tamandua_group}) %{_sharedstatedir}/tamandua/rules/yara
%dir %attr(0750,%{_tamandua_user},%{_tamandua_group}) %{_sharedstatedir}/tamandua/rules/sigma
%dir %attr(0750,%{_tamandua_user},%{_tamandua_group}) %{_localstatedir}/log/tamandua
%ghost /run/tamandua

%changelog
* %(date "+%a %b %d %Y") Tamandua Security <contato@treantlab.org> - %{_version}-%{_release}
- Release %{_version}
- See https://github.com/treant-lab/tamandua-agent/releases for full changelog
