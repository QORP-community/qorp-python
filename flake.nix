{
  description = "QORP";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        env = pkgs.poetry2nix.mkPoetryEnv {
          projectDir = ./.;
          editablePackageSources = {
            app = ./qorp;
          };
        };
      in
      {
        devShells.default = env.env.overrideAttrs (oldAttrs: {
          buildInputs = with pkgs; [ python3 poetry python3Packages.jedi-language-server ];
        });
      }
    );
}
