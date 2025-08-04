{
  description = "pwn flake";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.systems.url = "github:nix-systems/default";
  inputs.flake-utils = {
    url = "github:numtide/flake-utils";
    inputs.systems.follows = "systems";
  };
  inputs.rust-overlay.url = "github:oxalica/rust-overlay";

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [
          rust-overlay.overlays.default
          (final: prev: {
            # Optional: custom package from GitHub
            my-ropr = final.rustPlatform.buildRustPackage rec {
              pname = "ropr";
              version = "0.2.25";
              src = final.fetchFromGitHub {
                owner = "Ben-Lichtman";
                repo = "ropr";
                rev = version;
                sha256 = "sha256-LfQp7knYlwzxyfA7NolYu9RQQAR3eBir6ULEiUOhQ7s=";
              };

              cargoHash = "sha256-E1p4xfXNPbaPh5tE6uTkmmMsVk39NXNM8hhWpspTQjs="; # replace with actual hash
            };
          })
          (
            final: prev:
            let
              vmlinux-to-elf =
                with final.python313.pkgs;
                buildPythonPackage rec {
                  name = "vmlinux-to-elf";
                  version = "da14e789596d493f305688e221e9e34ebf63cbb8";
                  format = "setuptools";
                  src = final.fetchFromGitHub {
                    owner = "marin-m";
                    repo = name;
                    rev = version;
                    sha256 = "sha256-GVoUIeJeLWCEFzrwiLX2h627ygQ7lX1qMp3hHT5O8O0=";
                    # sha256 = final.lib.fakeHash;
                  };
                };
              crccheck =
                with final.python313.pkgs;
                buildPythonPackage rec {
                  name = "crccheck";
                  version = "v1.3.0";
                  format = "setuptools";
                  src = final.fetchFromGitHub {
                    owner = "MartinScharrer";
                    repo = name;
                    tag = version;
                    sha256 = "sha256-nujt3RWupvCtk7gORejtSwqqVjW9VwztOVGXBHW9T+k=";
                    # sha256 = final.lib.fakeHash;
                  };
                };
              pythonPath =
                with final.python313.pkgs;
                makePythonPath [
                  crccheck
                  unicorn
                  capstone
                  ropper
                  keystone-engine
                  tqdm
                  magika
                  rpyc
                ];
              binPath =
                with final;
                lib.makeBinPath [
                  python313
                  bintools-unwrapped # for readelf
                  file
                  ps
                  vmlinux-to-elf
                  one_gadget
                  rubyPackages_3_3.seccomp-tools
                ];
            in
            {
              gef-bata24 = prev.gef.overrideAttrs (
                finalAttrs: oldAttrs: rec {
                  pname = "gef-bata24";
                  version = "dev";
                  src = final.fetchFromGitHub {
                    owner = "d0ublew";
                    repo = "gef";
                    rev = version;
                    sha256 = "sha256-PmkmmH58m3mmsD5q/O03GwEKoH9hVy0BMi6VLrhVY94=";
                    # sha256 = prev.lib.fakeHash;
                  };
                  installPhase = ''
                    mkdir -p $out/share/gef
                    cp gef.py $out/share/gef
                    cp gef-bata24.rc $out/share/gef/gef-bata24.rc
                    makeWrapper ${final.gdb}/bin/gdb $out/bin/gef-bata24 \
                    --add-flags "-q -x $out/share/gef/gef.py" \
                    --set GEF_RC $out/share/gef/gef-bata24.rc \
                    --set NIX_PYTHONPATH ${pythonPath} \
                    --prefix PATH : ${binPath}
                  '';
                }
              );
            }
          )
        ];
        # pkgs = nixpkgs.legacyPackages.${system};
        pkgs = import nixpkgs { inherit system overlays; };
        py3 = pkgs.python312.withPackages (
          pp: with pp; [
            pip
            pwntools
            tqdm
            ropgadget
          ]
        );
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bashInteractive
            py3
            patchelf
            gef-bata24
            my-ropr
          ];
        };
      }
    );
}
