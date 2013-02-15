%define major 0
%define minor 1
%define patchlevel 115
Name: tel-plugin-dbus_tapi
Summary: dbus-tapi plugin for telephony
Version:    %{major}.%{minor}.%{patchlevel}
Release:    1
Group:      System/Libraries
License:    Apache
Source0:    tel-plugin-dbus_tapi-%{version}.tar.gz
%ifarch %ix86
%if "%{simulator}" != "1"
patch0: 0001-desc-dbus-create-interfaces-when-modem-is-added.patch
patch1: 0002-sms-PDU-Trace-enhancement.patch
%endif
%endif
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gobject-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(tcore)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(appsvc)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  python
BuildRequires:  python-xml

%description
dbus-tapi plugin for telephony

%prep
%setup -q
%ifarch %ix86
%if "%{simulator}" != "1"
%patch0 -p1
%patch1 -p1
%endif
%endif

%build
versionint=$[%{major} * 1000000 + %{minor} * 1000 + %{patchlevel}]
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DVERSION=$versionint
make %{?jobs:-j%jobs}

%post
/sbin/ldconfig

%postun -p /sbin/ldconfig

%install
rm -rf %{buildroot}
%make_install
mkdir -p %{buildroot}/usr/share/license

%files
%defattr(-,root,root,-)
#%doc COPYING
%{_libdir}/telephony/plugins/*
%{_prefix}/etc/dbus-1/system.d/*
/usr/share/license/tel-plugin-dbus_tapi