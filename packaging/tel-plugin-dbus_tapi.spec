%define major 0
%define minor 1
%define patchlevel 218
Name: tel-plugin-dbus_tapi
Summary: dbus-tapi plugin for telephony
Version:    %{major}.%{minor}.%{patchlevel}
Release:    1
Group:      System/Libraries
License:    Apache-2.0
Source0:    tel-plugin-dbus_tapi-%{version}.tar.gz
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
cp LICENSE %{buildroot}/usr/share/license/%{name}

%files
%defattr(-,root,root,-)
#%doc COPYING
%{_libdir}/telephony/plugins/*
%{_prefix}/etc/dbus-1/system.d/*
/usr/share/license/%{name}
