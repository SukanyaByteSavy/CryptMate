{pkgs}: {
  deps = [
    pkgs.eigen
    pkgs.catch
    pkgs.gnumake
    pkgs.cmake
    pkgs.rustc
    pkgs.pkg-config
    pkgs.libxcrypt
    pkgs.libiconv
    pkgs.cargo
    pkgs.postgresql
    pkgs.openssl
  ];
}
