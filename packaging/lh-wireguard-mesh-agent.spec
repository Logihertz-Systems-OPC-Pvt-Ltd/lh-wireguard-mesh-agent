Name:           lh-wireguard-mesh-agent
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-wg-mesh - Symmetric Pairwise Post-Quantum Pre-Shared Key Derivation
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-wireguard-mesh-agent
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      %{_arch}

%description
Air-gapped Peer-to-Peer WireGuard mesh coordinator synthesizing N(N-1)/2 full-mesh configs with RFC 7748 Curve25519 key clamping, symmetric pairwise Post-Quantum PSKs, Ed25519 discovery beacons, and /32 route-hijack guards.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-wg-mesh ]; then
    install -m 0755 bin/lh-wg-mesh %{buildroot}%{_bindir}/lh-wg-mesh
elif [ -f lh-wg-mesh ]; then
    install -m 0755 lh-wg-mesh %{buildroot}%{_bindir}/lh-wg-mesh
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for lh-wireguard-mesh-agent.
