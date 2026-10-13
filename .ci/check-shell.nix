# Native headers for the Keyhole test server (OpenSSL via webauthn-rs-core).
{ pkgs ? import (builtins.fetchTarball {
  url = "https://github.com/NixOS/nixpkgs/archive/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436.tar.gz";
  sha256 = "sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=";
}) {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [ openssl ];
  nativeBuildInputs = with pkgs; [ pkg-config clang llvmPackages.libclang ];
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}
