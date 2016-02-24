%define major 0
%define minor 5
%define patchlevel 1

Name:           tel-plugin-dbus_tapi
Version:        %{major}.%{minor}.%{patchlevel}
Release:        2
License:        Apache-2.0
Summary:        dbus-tapi plugin for telephony
Group:          System/Libraries
Source0:        tel-plugin-dbus_tapi-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  python-xml
BuildRequires:  python
BuildRequires:  pkgconfig(appsvc)
BuildRequires:  pkgconfig(capi-appfw-app-manager)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(tcore)

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
dbus-tapi plugin for telephony

%prep
%setup -q

%build
versionint=$[%{major} * 1000000 + %{minor} * 1000 + %{patchlevel}]

cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DVERSION=$versionint \

make %{?_smp_mflags}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}%{_datadir}/license

%files
%manifest tel-plugin-dbus_tapi.manifest
%defattr(644,system,system,-)
#%doc COPYING
%{_libdir}/telephony/plugins/*
%{_datadir}/license/tel-plugin-dbus_tapi
